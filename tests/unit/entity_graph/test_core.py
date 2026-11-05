"""Roles, zero-trust checks and missing fields over the pure core. The first group is the
tool's own suite, on the same traffic shapes, in documentation address ranges."""

from dataclasses import asdict
from datetime import datetime, timezone

from core.entity_graph.build import CaseRef, build, entities_of_contexts, logs_query
from core.entity_graph.features import (
    DEFAULT_INTERNAL,
    Flow,
    FlowSet,
    Network,
    flows_from_rows,
)

NET = Network.of(DEFAULT_INTERNAL)
DC, FS, ADMIN = "198.51.100.10", "198.51.100.20", "192.0.2.40"
WS1, WS2 = "192.0.2.31", "192.0.2.32"
RARE, NET_EXT = "198.51.100.99", "203.0.113.8"
CLIENTS = [f"192.0.2.{i}" for i in range(30, 38)]


def flow(src, dst, sport, dport, n=1, fwd=500, bwd=800, proto="tcp", t0=1e6, step=1.0):
    return [
        Flow(src, dst, t0 + i * step, sport, dport, proto, fwd, bwd) for i in range(n)
    ]


def office():
    rows = []
    for c in CLIENTS:
        rows += flow(c, DC, 50000, 88, 3) + flow(c, DC, 50001, 389, 3)
        rows += flow(c, DC, 50002, 53, 5, proto="udp") + flow(c, DC, 50003, 445, 2)
        rows += flow(c, FS, 50004, 445, 4, fwd=200, bwd=90_000)
    return rows


def graph(flows, net=NET, **kwargs):
    return build(FlowSet(flows=flows), net, **kwargs)


def roles(g):
    return {n.id: n.role.primary for n in g.nodes}


def checks(g):
    return {f.check for f in g.findings}


def node(g, entity):
    return next(n for n in g.nodes if n.id == entity)


def edge(g, edge_id):
    return next(e for e in g.edges if e.id == edge_id)


def test_dc_file_server_and_workstations_from_traffic_alone():
    g = graph(office())
    r = roles(g)
    assert r[DC] == "domain_controller" and r[FS] == "file_server"
    assert r[WS1] == "workstation" and r[WS2] == "workstation"
    assert any("Kerberos" in e for e in node(g, DC).role.candidates[0].evidence)
    assert node(g, DC).role.band == "likely"


def test_reply_records_are_flipped_and_random_source_ports_are_not_services():
    rows = office()
    rows += flow(DC, WS1, 53, 50123, 3, proto="udp")
    rows += flow(WS1, "198.51.100.50", 1521, 6881, 3)
    g = graph(rows)
    assert not any(p.port == 1521 for p in node(g, WS1).stats.served_ports)
    assert roles(g)[WS1] == "workstation"


def test_admin_host_and_admin_protocols_from_workstations():
    rows = office()
    servers = [DC, FS, "198.51.100.30", "198.51.100.31", "198.51.100.32"]
    rows += [r for s in servers for r in flow(ADMIN, s, 51000, 3389, 2)]
    for s in servers[2:]:
        for c in ("192.0.2.33", "192.0.2.34", "192.0.2.35"):
            rows += flow(c, s, 50500, 443, 2)
    rows += flow(WS1, WS2, 52000, 445, 2)
    g = graph(rows)
    assert roles(g)[ADMIN] == "admin_workstation"
    assert "ZT1" in checks(g)
    assert not any(f.check == "ZT10" and ADMIN in f.hosts[1:] for f in g.findings)


def test_smb_and_rpc_to_dc_or_file_server_is_not_admin_traffic():
    assert "ZT10" not in checks(graph(office()))


def test_rare_destination_and_one_way_upload_across_segments():
    rows = office()
    rows += flow(WS1, RARE, 50999, 443, 40, fwd=300, bwd=300, step=60)
    rows += flow(WS2, RARE, 50998, 7000, 30, fwd=400_000, bwd=10)
    g = graph(rows)
    assert {"ZT14", "ZT15"} <= checks(g)
    upload = next(f for f in g.findings if f.check == "ZT15")
    assert WS2 in upload.hosts and "MB" in upload.detail


def test_periodic_connection_across_segments_is_a_beacon():
    rows = office() + flow(WS1, RARE, 50999, 443, 40, step=60)
    beacon = next(f for f in graph(rows).findings if f.check == "ZT13")
    assert "every ~60s" in beacon.detail


def test_cloud_uploads_spread_over_one_prefix_are_not_exfil():
    rows = office()
    for i, ws in enumerate(CLIENTS[:6]):
        rows += flow(ws, f"203.0.113.{10 + i}", 51111, 443, 10, fwd=1_000_000, bwd=1000)
    assert "ZT15" not in checks(graph(rows))


def test_internet_exposed_admin_needs_an_answer():
    rows = office() + flow(NET_EXT, DC, 40000, 3389, 3, bwd=0)
    assert "ZT3" not in checks(graph(rows))
    rows += flow(NET_EXT, DC, 40001, 3389, 3, bwd=900)
    assert "ZT3" in checks(graph(rows))


def test_loglm_anomalies_cross_segment_are_grouped_and_never_role_evidence():
    scored = [
        Flow(WS1, DC, 1e6 + i, 50010, 5985, "tcp", 500, 800, loglm=0.97)
        for i in range(4)
    ]
    g = graph(office() + scored)
    z9 = [f for f in g.findings if f.check == "ZT9"]
    assert len(z9) == 1 and "4 LogLM-anomalous flows" in z9[0].detail
    assert roles(g)[DC] == "domain_controller"
    assert edge(g, f"{WS1}->{DC}").loglm.anomalous == 4
    assert g.loglm is True


def test_loglm_shades_confidence_but_not_the_band():
    clean = node(graph(office()), DC).role
    scored = [
        Flow(c, DC, 1e6 + i, 50000, 88, "tcp", 500, 800, loglm=0.95)
        for i, c in enumerate(CLIENTS)
    ]
    shaded = node(graph(office() + scored), DC).role
    assert shaded.confidence < clean.confidence
    assert shaded.band == clean.band == "likely"


def test_flat_segment_detected_with_the_flows_behind_it():
    servers = [f"192.0.2.{i}" for i in (60, 61, 62, 63)]
    rows = office()
    for s in servers:
        for c in CLIENTS:
            rows += flow(c, s, 50600, 443, 3)
        rows += flow("192.0.2.70", s, 50700, 22, 2)
    g = graph(rows)
    assert roles(g)["192.0.2.70"] == "admin_workstation"
    flat = next(f for f in g.findings if f.check == "ZT4")
    assert flat.flows and all(x.source.startswith("192.0.2.") for x in flat.flows)
    assert flat.logs_query.startswith("ip:192.0.2.")


def test_internal_ranges_are_configurable():
    net = Network.of(["203.0.113.0/24"])
    rows = [
        r
        for i in range(5)
        for r in flow(f"203.0.113.{i + 1}", "203.0.113.50", 50000, 80, 3)
    ]
    n = node(graph(rows, net), "203.0.113.50")
    assert n.internal and n.role.primary == "web_server"
    assert not node(graph(rows), "203.0.113.50").internal


def test_ot_roles_and_it_reaching_ot_and_ot_calling_out():
    plc, hmi = "192.0.2.200", "192.0.2.201"
    rows = office()
    rows += flow(hmi, plc, 50000, 502, 5)
    rows += flow(hmi, "192.0.2.202", 50000, 502, 5)
    rows += flow(hmi, "192.0.2.203", 50000, 502, 5)
    rows += flow(WS1, plc, 50000, 502, 2)
    rows += flow(plc, NET_EXT, 50000, 443, 2)
    g = graph(rows)
    assert roles(g)[plc] == "ot_controller" and roles(g)[hmi] == "ot_master"
    assert {"ZT2", "ZT12"} <= checks(g)
    assert next(f for f in g.findings if f.check == "ZT2").flows[0].source == WS1


def test_kerberos_outside_the_dcs_names_its_clients():
    rogue = "192.0.2.90"
    rows = [r for c in CLIENTS[:4] for r in flow(c, rogue, 50000, 88, 2)]
    found = next(f for f in graph(rows).findings if f.check == "ZT5")
    assert {x.source for x in found.flows} == set(CLIENTS[:4])
    assert found.logs_query == f"ip:{rogue} ip:{','.join(CLIENTS[:4])} port:88,389"


def test_dns_to_the_internet_is_found_with_or_without_a_protocol():
    rows = office() + [Flow(WS1, NET_EXT, 1e6, 50000, 53, "", 80, 120)]
    assert "ZT6" in checks(graph(rows))


def test_a_host_reaching_many_segments_names_the_links():
    rows = office() + flow(WS1, "10.20.30.40", 50000, 443, 2)
    rows += flow(WS1, "172.16.5.9", 50000, 443, 2)
    found = next(f for f in graph(rows).findings if f.check == "ZT8")
    assert found.hosts == [WS1]
    assert {x.target for x in found.flows} >= {"10.20.30.40", "172.16.5.9"}


def test_a_service_on_a_workstation_names_its_clients():
    rows = office() + flow(WS1, DC, 50000, 443, 80)
    rows += [r for c in CLIENTS[2:5] for r in flow(c, WS1, 50000, 8081, 1)]
    assert roles(graph(rows))[WS1] == "workstation"
    found = next(f for f in graph(rows).findings if f.check == "ZT11")
    assert {x.source for x in found.flows} == set(CLIENTS[2:5])
    assert found.logs_query.endswith("port:8081")


def without_bytes(flows):
    return [
        Flow(f.src, f.dst, f.time, f.src_port, f.dst_port, f.proto, None, None)
        for f in flows
    ]


def test_no_byte_counts_keep_the_roles_but_stop_them_at_possible():
    full, bare = graph(office()), graph(without_bytes(office()))
    assert roles(bare)[DC] == "domain_controller"
    assert roles(bare)[FS] == "file_server"
    assert node(full, DC).role.band == "likely"
    assert node(bare, DC).role.band == "possible"
    assert node(bare, DC).role.confidence < node(full, DC).role.confidence
    assert "no byte counts" in node(bare, DC).role.limits[0]
    assert node(bare, DC).stats.bytes_in is None
    assert edge(bare, f"{WS1}->{DC}").bytes is None
    assert edge(bare, f"{WS1}->{DC}").answered is None


def test_no_byte_counts_mark_answer_findings_unconfirmed_and_say_what_did_not_run():
    rows = without_bytes(office() + flow(NET_EXT, DC, 40001, 3389, 3))
    g = graph(rows)
    exposed = next(f for f in g.findings if f.check == "ZT3")
    assert exposed.confirmed is False
    assert {c.check for c in g.checks_not_run} == {"ZT9", "ZT15"}
    assert g.coverage.with_bytes == 0 and g.loglm is False


def test_a_full_count_confirms_the_same_finding():
    g = graph(office() + flow(NET_EXT, DC, 40001, 3389, 3))
    assert next(f for f in g.findings if f.check == "ZT3").confirmed is True


def test_no_ports_draw_the_edge_and_claim_no_role_or_port_check():
    rows = [
        Flow(c, DC, 1e6 + i, None, None, "", None, None) for i, c in enumerate(CLIENTS)
    ]
    g = graph(rows)
    assert edge(g, f"{CLIENTS[0]}->{DC}").flows == 1
    assert set(roles(g).values()) == {"unknown"}
    assert not g.findings
    assert {"ZT1", "ZT3", "ZT7"} <= {c.check for c in g.checks_not_run}
    assert "no port" in node(g, DC).role.limits[-1]


def test_a_missing_source_port_never_flips_the_row():
    g = graph([Flow(WS1, RARE, 1e6, None, 4444, "tcp", 10, 10)])
    assert edge(g, f"{WS1}->{RARE}").source == WS1


def rows_of(*rows):
    at = datetime(2026, 1, 5, 12, tzinfo=timezone.utc)
    return [{"time": at, **row} for row in rows]


def test_rows_read_the_two_ends_and_the_source_record():
    rows = rows_of(
        {
            "src_ip": "192.0.2.5",
            "src_host": "WKS-05",
            "dst_ip": "198.51.100.7",
            "dst_port": 445,
            "action": "allow",
            "loglm": 0.8,
            "raw": {
                "id.orig_p": "51000",
                "proto": "6",
                "orig_bytes": 10,
                "resp_bytes": "20",
            },
        }
    )
    out = flows_from_rows(rows)
    assert out.flows == [
        Flow(
            "192.0.2.5",
            "198.51.100.7",
            rows[0]["time"].timestamp(),
            51000,
            445,
            "tcp",
            10,
            20,
            0.8,
        )
    ]
    assert out.names == {"192.0.2.5": "WKS-05"}


def test_rows_read_a_firewall_export_with_its_own_field_names():
    raw = {
        "Source Port": "51000",
        "IP Protocol": "tcp",
        "Bytes Sent": 10,
        "Bytes Received": 20,
    }
    rows = rows_of(
        {"src_ip": "192.0.2.5", "dst_ip": "198.51.100.7", "dst_port": 443, "raw": raw}
    )
    f = flows_from_rows(rows).flows[0]
    assert (f.src_port, f.proto, f.bytes_fwd, f.bytes_bwd) == (51000, "tcp", 10, 20)


def test_rows_without_both_ends_or_with_one_machine_are_skipped_and_counted():
    rows = rows_of(
        {"src_ip": "192.0.2.5"},
        {"dst_host": "wks-05"},
        {"src_ip": "192.0.2.5", "dst_ip": "192.0.2.5"},
        {"src_ip": "127.0.0.1", "dst_ip": "192.0.2.5"},
        {"src_host": "-", "dst_ip": "192.0.2.5"},
        {"src_ip": "192.0.2.5", "dst_ip": "198.51.100.7"},
    )
    out = flows_from_rows(rows)
    assert out.skipped == 5 and len(out.flows) == 1


def test_a_dns_query_name_does_not_name_the_resolver():
    rows = rows_of(
        {
            "src_ip": "192.0.2.5",
            "dst_ip": "198.51.100.7",
            "dst_host": "updates.example.net",
            "event_class": "DNS",
        },
        {"src_ip": "192.0.2.5", "dst_ip": "198.51.100.7", "dst_host": "dc-01"},
    )
    out = flows_from_rows(rows)
    assert out.names["198.51.100.7"] == "dc-01"
    assert "updates.example.net" not in out.aliases


def test_a_name_seen_with_an_address_is_the_same_node():
    rows = rows_of(
        {"src_ip": "192.0.2.5", "src_host": "WKS-05", "dst_ip": "198.51.100.7"},
        {"src_host": "wks-05", "dst_host": "fs-01"},
    )
    out = flows_from_rows(rows)
    assert {f.src for f in out.flows} == {"192.0.2.5"}
    g = build(out, NET)
    assert node(g, "192.0.2.5").label == "WKS-05"
    assert node(g, "fs-01").internal and node(g, "fs-01").subnet == "named"


def test_a_name_on_an_outside_domain_is_external_and_never_crashes_on_dots():
    rows = rows_of(
        {"src_ip": "192.0.2.5", "dst_host": "a.b.example.org", "dst_port": 443}
    )
    g = build(flows_from_rows(rows), NET)
    assert node(g, "a.b.example.org").role.primary == "external"


def test_a_denied_flow_is_known_to_be_unanswered():
    rows = rows_of(
        {"src_ip": "203.0.113.8", "dst_ip": DC, "dst_port": 3389, "action": "deny"}
    )
    g = build(flows_from_rows(rows), NET)
    assert edge(g, f"203.0.113.8->{DC}").answered is False
    assert "ZT3" not in checks(g)


def test_nonsense_values_in_a_source_record_are_absent_not_fatal():
    rows = rows_of(
        {
            "src_ip": "192.0.2.5",
            "dst_ip": "198.51.100.7",
            "dst_port": 99999,
            "loglm": float("nan"),
            "raw": {"src_port": "x", "bytes_out": "-3", "bytes_in": "inf"},
        }
    )
    f = flows_from_rows(rows).flows[0]
    assert (f.dst_port, f.src_port, f.bytes_fwd, f.bytes_bwd, f.loglm) == (
        None,
        None,
        None,
        None,
        None,
    )


def test_case_path_marks_edges_between_its_entities_in_time_order():
    rows = office()
    rows += flow(WS1, FS, 50020, 445, 2, t0=2e6)
    rows += flow(FS, NET_EXT, 50021, 443, 2, t0=3e6)
    case = CaseRef("case-1", "A case", [WS1, FS, NET_EXT, "gone-host"])
    g = graph(rows, case=case)
    assert [(h.source, h.target) for h in g.path.hops] == [
        (WS1, FS),
        (FS, NET_EXT),
    ]
    assert g.path.not_seen == ["gone-host"]
    assert node(g, FS).on_path and not node(g, DC).on_path
    assert edge(g, f"{FS}->{NET_EXT}").on_path
    assert not edge(g, f"{WS1}->{DC}").on_path


def test_case_entities_given_as_names_resolve_to_their_address():
    rows = rows_of(
        {"src_ip": "192.0.2.5", "src_host": "WKS-05", "dst_ip": "198.51.100.7"},
    )
    g = build(
        flows_from_rows(rows),
        NET,
        case=CaseRef("case-1", "A case", ["wks-05", "198.51.100.7"]),
    )
    assert [(h.source, h.target) for h in g.path.hops] == [
        ("192.0.2.5", "198.51.100.7")
    ]
    assert g.path.not_seen == []


def test_entities_of_contexts_reads_addresses_and_names_only():
    found = entities_of_contexts(
        [
            {"src_ips": ["192.0.2.5"], "hostnames": ["WKS-05"], "usernames": ["sam"]},
            {"dest_ip": "203.0.113.8", "domain": "bad.example.org"},
            None,
        ]
    )
    assert found == ["192.0.2.5", "203.0.113.8", "bad.example.org", "wks-05"]


def test_logs_query_names_both_ends_on_the_finding_ports():
    assert logs_query([(WS1, DC)], [445]) == f"ip:{WS1} ip:{DC} port:445"
    assert logs_query([(WS1, DC), (WS2, DC)], []) == f"ip:{DC} ip:{WS1},{WS2}"
    assert logs_query([("wks-1", "fs-1")], []) == "host:wks-1 host:fs-1"


def test_logs_query_falls_back_to_the_shared_prefix_when_the_list_is_long():
    pairs = [(f"192.0.2.{i}", f"192.0.2.{i + 100}") for i in range(1, 30)]
    assert logs_query(pairs, []) == "ip:192.0.2."


def test_every_finding_carries_flows_and_a_logs_query():
    rows = office() + flow(WS1, WS2, 52000, 445, 2) + flow(NET_EXT, DC, 40001, 3389, 3)
    for f in graph(rows).findings:
        assert f.flows and f.flows_total >= len(f.flows)
        assert f.logs_query.startswith(("ip:", "host:"))


def test_the_edge_cap_keeps_what_a_finding_rests_on_and_reports_the_rest():
    g = graph(office() + flow(NET_EXT, DC, 40001, 3389, 1), max_edges=2)
    assert len(g.edges) == 2 and all(e.findings for e in g.edges)
    assert g.truncated.edges > 0
    assert any(f.check == "ZT3" and f.flows for f in g.findings)


def test_the_graph_serializes_to_plain_data():
    payload = asdict(graph(office()))
    assert payload["nodes"][0]["role"]["candidates"][0]["evidence"]
    assert payload["path"] is None
