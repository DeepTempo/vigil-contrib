"""GET /api/entity-graph through the app and real Postgres, over rows inserted directly."""

from datetime import timedelta
from itertools import count

import pytest

from core.entity_graph import store
from core.storage.models import Case, Finding, LogEvent
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

pytestmark = [pytest.mark.unit, pytest.mark.database]

URL = "/api/entity-graph"
DC, FS = "198.51.100.10", "198.51.100.20"
WS1, WS2 = "192.0.2.31", "192.0.2.32"
EXT = "203.0.113.8"
CLIENTS = [f"192.0.2.{i}" for i in range(30, 38)]

ids = count(1)


def event(src_ip=None, dst_ip=None, *, ago=timedelta(hours=1), raw=None, **fields):
    n = next(ids)
    return LogEvent(
        event_id=f"eg-{n}",
        time=utcnow() - ago,
        source="zeek",
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw=raw or {},
        **fields,
    )


def answered(src, dst, port, **fields):
    return event(
        src,
        dst,
        dst_port=port,
        raw={"src_port": 51000, "orig_bytes": 400, "resp_bytes": 900},
        **fields,
    )


def store_rows(*rows):
    with unit_of_work() as session:
        session.add_all(rows)


def office_rows():
    rows = []
    for c in CLIENTS:
        rows += [answered(c, DC, 88), answered(c, DC, 389), answered(c, DC, 445)]
        rows += [answered(c, FS, 445) for _ in range(3)]
    return rows


def by_id(items):
    return {item["id"]: item for item in items}


def a_case(case_id, *contexts):
    with unit_of_work() as session:
        case = Case(case_id=case_id, title="Beacon from a workstation")
        for i, context in enumerate(contexts):
            case.findings.append(
                Finding(
                    finding_id=f"{case_id}-f{i}",
                    data_source="sample",
                    entity_context=context,
                    severity="high",
                )
            )
        session.add(case)


def test_an_empty_store_returns_an_empty_graph_with_its_counts(client, analyst):
    body = client.get(URL).json()
    assert body["nodes"] == [] and body["edges"] == [] and body["findings"] == []
    assert body["loglm"] is False
    assert body["rows"] == {
        "in_window": 0,
        "read": 0,
        "flows": 0,
        "skipped": 0,
        "cap": store.ROW_CAP,
        "capped": 0,
    }


def test_stored_rows_become_roles_edges_blocks_and_findings(client, analyst):
    store_rows(*office_rows(), answered(EXT, DC, 3389))
    body = client.get(URL).json()
    nodes = by_id(body["nodes"])
    dc = nodes[DC]
    assert dc["role"]["primary"] == "domain_controller"
    assert dc["role"]["confidence"] > 0
    assert any("Kerberos" in e for e in dc["role"]["candidates"][0]["evidence"])
    assert dc["block"] == "198.51.100.0/24|Identity & naming"
    assert nodes[CLIENTS[0]]["role"]["primary"] == "workstation"

    edge = by_id(body["edges"])[f"{CLIENTS[0]}->{DC}"]
    assert edge["flows"] == 3 and edge["answered"] is True
    assert {s["port"] for s in edge["services"]} == {88, 389, 445}

    assert {b["id"] for b in body["blocks"]} >= {
        "internet",
        "192.0.2.0/24|Workstations",
        "198.51.100.0/24|Identity & naming",
    }
    exposed = next(f for f in body["findings"] if f["check"] == "ZT3")
    assert exposed["confirmed"] is True
    assert exposed["flows"][0]["source"] == EXT and exposed["flows"][0]["flows"] == 1
    assert exposed["logs_query"] == f"ip:{EXT} ip:{DC} port:3389"
    assert body["coverage"]["with_bytes"] == body["coverage"]["flows"]


def test_rows_without_both_ends_are_skipped_and_counted(client, analyst):
    store_rows(
        answered(WS1, DC, 88),
        event(WS1, None, dst_port=443),
        event(None, DC),
        event(None, None, summary="a process started"),
        event(WS1, WS1),
    )
    rows = client.get(URL).json()["rows"]
    assert rows["in_window"] == 5
    assert rows["flows"] == 1
    assert rows["skipped"] == 4


def test_rows_with_host_names_only_are_flows(client, analyst):
    store_rows(
        LogEvent(
            event_id="eg-names",
            time=utcnow() - timedelta(hours=1),
            source="winsec",
            src_host="WKS-07",
            dst_host="FS-02",
            dst_port=445,
        )
    )
    body = client.get(URL).json()
    assert {n["id"] for n in body["nodes"]} == {"wks-07", "fs-02"}
    assert body["findings"] == [] or all(
        f["logs_query"].startswith("host:") for f in body["findings"]
    )


def test_the_window_bounds_the_rows(client, analyst):
    store_rows(answered(WS1, DC, 88), answered(WS2, DC, 88, ago=timedelta(hours=30)))
    assert {n["id"] for n in client.get(URL, params={"hours": 24}).json()["nodes"]} == {
        WS1,
        DC,
    }
    wide = client.get(URL, params={"hours": 48}).json()
    assert {n["id"] for n in wide["nodes"]} == {WS1, WS2, DC}
    assert wide["window"]["hours"] == 48


def test_hours_out_of_range_is_refused(client, analyst):
    assert client.get(URL, params={"hours": 0}).status_code == 422
    assert client.get(URL, params={"hours": store.MAX_HOURS + 1}).status_code == 422


def test_the_cap_keeps_the_newest_rows_and_says_how_many_it_left(client, analyst):
    store_rows(
        answered(WS1, DC, 88, ago=timedelta(hours=1)),
        answered(WS2, DC, 88, ago=timedelta(hours=2)),
        answered(CLIENTS[0], DC, 88, ago=timedelta(hours=3)),
    )
    payload = store.entity_graph_payload(24, row_cap=1)
    assert {n["id"] for n in payload["nodes"]} == {WS1, DC}
    assert payload["rows"]["read"] == 1
    assert payload["rows"]["capped"] == 2
    assert payload["rows"]["cap"] == 1


def test_rows_with_no_bytes_or_ports_degrade_through_the_response(client, analyst):
    rows = [event(c, DC, dst_port=port) for c in CLIENTS for port in (88, 389, 445)]
    store_rows(*rows, event(EXT, DC, dst_port=3389))
    body = client.get(URL).json()
    dc = by_id(body["nodes"])[DC]
    assert dc["role"]["primary"] == "domain_controller"
    assert dc["role"]["band"] == "possible"
    assert "no byte counts" in dc["role"]["limits"][0]
    assert by_id(body["edges"])[f"{CLIENTS[0]}->{DC}"]["bytes"] is None
    exposed = next(f for f in body["findings"] if f["check"] == "ZT3")
    assert exposed["confirmed"] is False
    assert "ZT15" in {c["check"] for c in body["checks_not_run"]}


def test_without_loglm_the_flag_is_off_and_with_it_edges_carry_the_score(
    client, analyst
):
    store_rows(answered(WS1, DC, 5985))
    off = client.get(URL).json()
    assert off["loglm"] is False
    assert off["edges"][0]["loglm"] == {"scored": 0, "anomalous": 0, "max_score": None}
    assert "ZT9" in {c["check"] for c in off["checks_not_run"]}

    store_rows(answered(WS1, DC, 5985, loglm=0.91))
    on = client.get(URL).json()
    assert on["loglm"] is True
    assert by_id(on["edges"])[f"{WS1}->{DC}"]["loglm"] == {
        "scored": 1,
        "anomalous": 1,
        "max_score": 0.91,
    }
    assert any(f["check"] == "ZT9" for f in on["findings"])
    assert not any(c["check"] == "ZT9" for c in on["checks_not_run"])


def test_a_case_marks_the_path_through_its_entities(client, analyst):
    store_rows(
        *office_rows(),
        answered(WS1, FS, 22, ago=timedelta(hours=3)),
        answered(FS, EXT, 443, ago=timedelta(hours=2)),
    )
    a_case(
        "eg-case-1",
        {"src_ips": [WS1], "hostnames": ["never-seen-host"]},
        {"dest_ips": [EXT], "src_ip": FS, "usernames": ["sam"]},
    )
    body = client.get(URL, params={"case_id": "eg-case-1"}).json()
    path = body["path"]
    assert path["case_id"] == "eg-case-1"
    assert path["title"] == "Beacon from a workstation"
    assert (path["hops"][0]["source"], path["hops"][0]["target"]) == (WS1, FS)
    assert (path["hops"][-1]["source"], path["hops"][-1]["target"]) == (FS, EXT)
    assert path["not_seen"] == ["never-seen-host"]
    nodes, edges = by_id(body["nodes"]), by_id(body["edges"])
    assert nodes[WS1]["on_path"] and nodes[EXT]["on_path"]
    assert not nodes[DC]["on_path"]
    assert edges[f"{FS}->{EXT}"]["on_path"]
    assert not edges[f"{CLIENTS[0]}->{FS}"]["on_path"]


def test_a_graph_without_a_case_has_no_path_and_an_unknown_case_is_404(client, analyst):
    store_rows(answered(WS1, DC, 88))
    assert client.get(URL).json()["path"] is None
    assert client.get(URL, params={"case_id": "eg-missing"}).status_code == 404


def test_it_takes_findings_read_and_a_case_also_takes_cases_read(
    client, custom_role_user
):
    a_case("eg-case-2", {"src_ips": [WS1]})
    custom_role_user("loglm.view")
    assert client.get(URL).status_code == 403
    custom_role_user("findings.read")
    assert client.get(URL).status_code == 200
    refused = client.get(URL, params={"case_id": "eg-case-2"})
    assert refused.status_code == 403 and "cases.read" in refused.text
    custom_role_user("findings.read", "cases.read")
    assert client.get(URL, params={"case_id": "eg-case-2"}).status_code == 200


def test_the_operator_can_name_the_internal_ranges(client, analyst, monkeypatch):
    store_rows(answered(EXT, WS1, 443))
    assert client.get(URL).json()["internal_ranges"][0] == "10.0.0.0/8"
    monkeypatch.setenv(store.INTERNAL_CIDRS_ENV, "203.0.113.0/24, not-a-range")
    body = client.get(URL).json()
    assert body["internal_ranges"] == ["203.0.113.0/24"]
    nodes = by_id(body["nodes"])
    assert nodes[EXT]["internal"] and not nodes[WS1]["internal"]


def test_the_window_is_an_aware_utc_range():
    from datetime import datetime, timedelta

    from core.entity_graph.store import entity_graph_payload

    window = entity_graph_payload(1)["window"]
    start = datetime.fromisoformat(window["start"])
    end = datetime.fromisoformat(window["end"])
    assert start.utcoffset() == timedelta(0)
    assert end - start == timedelta(hours=1)
