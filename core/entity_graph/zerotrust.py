"""Zero-trust posture checks over the host and block map.

Each check reads flows, inferred roles and blocks, and returns findings that name the
hosts and edges involved, why it matters (with its source), and the usual false positive.
Roles below the "possible" band never trigger a check.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

from core.entity_graph.features import ADMIN_PORTS, Edge, Host, Network
from core.entity_graph.roles import OT_PORTS, ROLES, RoleResult

SERVER_GROUPS = {"Servers", "Identity & naming"}
CLEARTEXT = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    161: "SNMP",
    389: "LDAP",
    110: "POP3",
    143: "IMAP",
}

CHECKS = {
    "ZT1": (
        "Workstation-to-workstation admin protocol",
        "high",
        "Remote services between workstations are the classic lateral-movement path "
        "(MITRE T1021); NIST SP 800-82r3 §5.2.3 limits reachability inside a segment.",
        "Helpdesk / RMM tools, small-office file sharing.",
    ),
    "ZT2": (
        "IT reaches OT directly",
        "critical",
        "IT hosts must not talk to Purdue levels 0-2 without a DMZ "
        "(NIST SP 800-82r3 §5.2.3).",
        "Zone mislabelled; historian replication through level 3.",
    ),
    "ZT3": (
        "Admin or OT port reachable from outside",
        "critical",
        "Network location grants no trust (NIST SP 800-207 tenet 2); direct external "
        "admin access is a top intrusion path.",
        "An intended bastion or VPN; scanners (the check requires bytes both ways).",
    ),
    "ZT4": (
        "Flat segment",
        "high",
        "One segment mixes servers, workstations and admin hosts: an implicit trust zone "
        "(SP 800-207 §2; CISA ZTMM v2 Networks, 'Traditional' macro-segmentation).",
        "Small lab or test network.",
    ),
    "ZT5": (
        "Directory service outside the DCs",
        "high",
        "Kerberos/LDAP answered by a non-DC host breaks the identity boundary "
        "(SP 800-207 tenets 4-5).",
        "Linux KDC, NAC appliance, or a role mis-inference.",
    ),
    "ZT6": (
        "DNS bypasses internal resolvers",
        "medium",
        "Traffic should be visible and inspected (SP 800-207 §3.4.1; ZTMM visibility).",
        "Guest or BYOD networks; DoH is invisible to this check.",
    ),
    "ZT7": (
        "Cleartext protocol to a server",
        "medium",
        "ZTMM v2 Traffic Encryption: encrypt internal traffic; SP 800-207 tenet 2.",
        "The port does not prove there was no TLS (check ssl logs); OT protocols are "
        "cleartext by design.",
    ),
    "ZT8": (
        "Host reaches many segments",
        "medium",
        "Least privilege per session (SP 800-207 tenet 3); lateral movement by a "
        "compromised account (§5.3).",
        "Scanners, SCCM, backup and monitoring hosts.",
    ),
    "ZT9": (
        "LogLM-anomalous traffic crosses a segment boundary",
        "high",
        "Use behavioural signals for access decisions (SP 800-207 tenet 4, §5.4; ZTMM "
        "anomaly detection).",
        "Model drift; authorised scan windows.",
    ),
    "ZT10": (
        "Admin protocol from a host that is not an admin host",
        "high",
        "Administrative access should come from managed jump/admin hosts only "
        "(SP 800-207 tenet 3; SP 800-82r3 remote-access guidance).",
        "An unlabelled admin machine.",
    ),
    "ZT11": (
        "Unexpected service on a workstation",
        "medium",
        "Unmanaged services widen the attack surface (SP 800-207 tenet 5).",
        "Developer test servers, printer web UIs.",
    ),
    "ZT12": (
        "OT host initiates outbound",
        "high",
        "Outbound rules for OT should be as strict as inbound (SP 800-82r3).",
        "NTP; historian push to the DMZ; vendor telemetry.",
    ),
    "ZT13": (
        "Beacon-like periodic connection across segments",
        "high",
        "Regular, low-jitter connections to one destination are typical of "
        "command-and-control (MITRE T1071/T1573); cross-segment egress should be "
        "explicit (ZTMM traffic management).",
        "Health checks, update agents, monitoring polls.",
    ),
    "ZT14": (
        "Rare cross-segment destination",
        "high",
        "A destination in another segment that almost nothing else talks to is a typical "
        "C2 or staging host (SP 800-207 tenet 4, behavioural signals; ZTMM traffic "
        "management).",
        "A new or niche internal service; one-off migrations.",
    ),
    "ZT15": (
        "Large one-way transfer across segments",
        "high",
        "Bulk upload to another segment or the internet with little coming back matches "
        "exfiltration (MITRE T1041/T1048); data flows should be explicit (ZTMM Data "
        "pillar).",
        "Backups, log shipping, file sync.",
    ),
}

# Checks that need something every flow may lack. Reported as not run when none has it.
NEEDS_PORTS = ("ZT1", "ZT2", "ZT3", "ZT5", "ZT6", "ZT7", "ZT10", "ZT11")
NEEDS_BYTES = ("ZT15",)
NEEDS_LOGLM = ("ZT9",)
# Checks that ask whether a service answered, which only a byte count can confirm.
NEEDS_ANSWER = {"ZT1", "ZT3", "ZT5", "ZT7", "ZT10", "ZT11"}


@dataclass
class Finding:
    check: str
    hosts: list[str]
    edges: list[tuple[str, str]] = field(default_factory=list)
    detail: str = ""
    ports: list[int] = field(default_factory=list)
    confirmed: bool = True

    @property
    def title(self) -> str:
        return CHECKS[self.check][0]

    @property
    def severity(self) -> str:
        return CHECKS[self.check][1]

    @property
    def why(self) -> str:
        return CHECKS[self.check][2]

    @property
    def false_positive_note(self) -> str:
        return CHECKS[self.check][3]


def _prefix(ip: str) -> str:
    return ".".join(ip.split(".")[:2]) + ".0.0/16"


def _role(roles: dict[str, RoleResult], ip: str) -> str:
    r = roles.get(ip)
    return r.primary if r and r.band != "unknown" else "unknown"


def _group(roles: dict[str, RoleResult], ip: str) -> str:
    return ROLES[_role(roles, ip)][1]


def _admin_ports(e: Edge, target_role: str = "") -> list[int]:
    # A scan's SYNs do not count, so a flow known to have gone unanswered is out. SMB/RPC
    # to a DC or file server is what domain members do all day, not admin.
    if e.answered is False:
        return []
    ports = {p for (p, _) in e.services if p in ADMIN_PORTS}
    if target_role in ("domain_controller", "file_server", "dns"):
        ports -= {135, 445}
    return sorted(ports)


def run_checks(
    hosts: dict[str, Host],
    edges: dict[tuple[str, str], Edge],
    roles: dict[str, RoleResult],
    net: Network,
) -> list[Finding]:
    out: list[Finding] = []
    cleartext: dict[tuple[str, int], list[tuple[str, str]]] = {}
    grouped: dict[tuple[str, str, int], list[tuple[str, str]]] = {}
    anomalous_cross: dict[tuple[str, str], list[Edge]] = {}
    # Rarity of an internet destination is judged by its /16: cloud services rotate IPs,
    # so per-IP rarity would call every large provider's endpoint "rare".
    prefix_clients: dict[str, set[str]] = {}
    for a, b in edges:
        if hosts[a].internal and not hosts[b].internal:
            prefix_clients.setdefault(_prefix(b), set()).add(a)
    seg = net.subnet_of
    internal = {ip for ip, h in hosts.items() if h.internal}

    for (a, b), e in edges.items():
        ra, rb, ga, gb = (
            _role(roles, a),
            _role(roles, b),
            _group(roles, a),
            _group(roles, b),
        )
        admin = _admin_ports(e, rb)
        served_ports = {p for (p, _) in e.services}
        if admin and ra == "workstation" and rb == "workstation":
            out.append(
                Finding(
                    "ZT1",
                    [a, b],
                    [(a, b)],
                    f"{a} → {b} on {', '.join(map(str, admin))}",
                    admin,
                )
            )
        if admin and a not in internal and b in internal:
            for p in admin:
                grouped.setdefault(("ZT3", b, p), []).append((a, b))
        ot_ports = sorted(served_ports & OT_PORTS)
        if ot_ports and a not in internal and b in internal and e.answered is not False:
            out.append(
                Finding(
                    "ZT3",
                    [a, b],
                    [(a, b)],
                    f"external {a} reached OT port(s) {ot_ports} on {b}",
                    ot_ports,
                )
            )
        if ot_ports and ga != "OT" and gb == "OT":
            out.append(
                Finding(
                    "ZT2",
                    [a, b],
                    [(a, b)],
                    f"{ra} {a} → OT {b} on {ot_ports}",
                    ot_ports,
                )
            )
        if ga == "OT" and gb != "OT":
            out.append(
                Finding(
                    "ZT12", [a, b], [(a, b)], f"OT {a} opened a connection to {rb} {b}"
                )
            )
        if (
            admin
            and a in internal
            and b in internal
            and ra not in ("admin_workstation", "domain_controller", "scanner")
            and gb in SERVER_GROUPS | {"Workstations", "Admin", "Unknown"}
        ):
            for p in admin:
                grouped.setdefault(("ZT10", b, p), []).append((a, b))
        clear = sorted(served_ports & CLEARTEXT.keys())
        if clear and gb in SERVER_GROUPS and e.answered is not False and a in internal:
            for p in clear:
                cleartext.setdefault((b, p), []).append((a, b))
        if served_ports & {53, 853}:
            if a in internal and b not in internal and not net.is_metadata(b):
                grouped.setdefault(("ZT6", b, 53), []).append((a, b))
        if e.seq_anomalous and seg(a) != seg(b) and a in internal and b in internal:
            anomalous_cross.setdefault(tuple(sorted((seg(a), seg(b)))), []).append(e)
        # A beacon is an internal host calling out; inbound health checks are not.
        if len(e.starts) >= 20 and seg(a) != seg(b) and a in internal:
            ts = sorted(e.starts)
            gaps = [y - x for x, y in zip(ts, ts[1:]) if y > x]
            if len(gaps) >= 15:
                mean = statistics.mean(gaps)
                cv = statistics.pstdev(gaps) / mean if mean else 9
                if cv < 0.35 and mean >= 5:
                    out.append(
                        Finding(
                            "ZT13",
                            [a, b],
                            [(a, b)],
                            f"{a} → {b}: {len(ts)} connections every ~{mean:.0f}s "
                            f"(jitter {cv:.2f})",
                        )
                    )

        if a in internal and seg(a) != seg(b) and gb != "Infrastructure":
            if (
                b in internal
                and len(hosts[b].peers_in) <= 2
                and (e.flows >= 20 or e.bytes_fwd + e.bytes_bwd >= 1_000_000)
            ):
                out.append(
                    Finding(
                        "ZT14",
                        [a, b],
                        [(a, b)],
                        f"{a} → {b} ({e.flows} connections); only "
                        f"{len(hosts[b].peers_in)} host(s) ever talk to {b}",
                    )
                )
            rare_dst = (
                len(hosts[b].peers_in) <= 2
                if b in internal
                else len(prefix_clients.get(_prefix(b), ())) <= 2
            )
            if (
                rare_dst
                and e.bytes_fwd >= 5_000_000
                and e.bytes_fwd >= 20 * max(e.bytes_bwd, 1)
            ):
                ports = sorted(served_ports)
                out.append(
                    Finding(
                        "ZT15",
                        [a, b],
                        [(a, b)],
                        f"{a} sent {e.bytes_fwd / 1e6:.1f} MB to {b} on {ports} and got "
                        f"{e.bytes_bwd / 1e3:.1f} KB back",
                        ports,
                    )
                )

    for (sa, sb), es in anomalous_cross.items():
        es = sorted(es, key=lambda e: -e.seq_anomalous)
        top = ", ".join(f"{e.src}→{e.dst} ({e.seq_anomalous})" for e in es[:4])
        out.append(
            Finding(
                "ZT9",
                sorted({x for e in es for x in (e.src, e.dst)}),
                [(e.src, e.dst) for e in es],
                f"{sum(e.seq_anomalous for e in es)} LogLM-anomalous flows on "
                f"{len(es)} host pairs between {sa} and {sb}, max score "
                f"{max(e.max_anomaly_conf for e in es):.2f}: {top}",
            )
        )

    names = {
        "ZT3": ("internet source", "internet sources"),
        "ZT10": ("non-admin host", "non-admin hosts"),
        "ZT6": ("internal host", "internal hosts"),
    }
    for (check, target, p), pairs in grouped.items():
        clients = sorted({x for x, _ in pairs})
        label = ROLES[_role(roles, target)][0].lower()
        one = len(clients) == 1
        who = f"{len(clients)} {names[check][0 if one else 1]}"
        text = (
            f"{who} {'resolves' if one else 'resolve'} names at external {target}"
            if check == "ZT6"
            else f"{who} {'reaches' if one else 'reach'} {label} {target} on {p}"
        )
        shown = f"{', '.join(clients[:4])}{'…' if len(clients) > 4 else ''}"
        out.append(Finding(check, [target, *clients], pairs, f"{text} ({shown})", [p]))

    for (srv, p), pairs in cleartext.items():
        clients = sorted({x for x, _ in pairs})
        out.append(
            Finding(
                "ZT7",
                [srv, *clients],
                pairs,
                f"{len(clients)} {'client uses' if len(clients) == 1 else 'clients use'} "
                f"{CLEARTEXT[p]} to "
                f"{ROLES[_role(roles, srv)][0].lower()} {srv}",
                [p],
            )
        )

    for ip, h in hosts.items():
        r = _role(roles, ip)
        if r != "domain_controller" and h.internal:
            dirsvc = h.served_clients(88) | h.served_clients(389)
            if len(dirsvc) >= 3:
                out.append(
                    Finding(
                        "ZT5",
                        [ip],
                        [(c, ip) for c in sorted(dirsvc)],
                        f"{ip} ({ROLES[r][0]}) answers Kerberos/LDAP for "
                        f"{len(dirsvc)} clients",
                        [88, 389],
                    )
                )
        if r == "workstation":
            for (p, _), cl in h.served.items():
                if len(cl) >= 3 and p < 49152:
                    out.append(
                        Finding(
                            "ZT11",
                            [ip],
                            [(c, ip) for c in sorted(cl)],
                            f"workstation {ip} serves {p} to {len(cl)} clients",
                            [p],
                        )
                    )
        if h.internal and r not in (
            "domain_controller",
            "dns",
            "scanner",
            "gateway",
            "cloud_infra",
        ):
            reached = sorted(
                p for p in h.peers_out if p in internal and seg(p) != seg(ip)
            )
            segs = {seg(p) for p in reached}
            if len(segs) >= 2:
                out.append(
                    Finding(
                        "ZT8",
                        [ip],
                        [(ip, p) for p in reached],
                        f"{ip} ({ROLES[r][0]}) reaches {len(segs) + 1} segments: "
                        + ", ".join(sorted(segs)),
                    )
                )

    by_seg: dict[str, set[str]] = {}
    for ip in internal:
        g = _group(roles, ip)
        if g in ("Servers", "Identity & naming", "Workstations", "Admin", "OT"):
            by_seg.setdefault(seg(ip), set()).add(g)
    for s, groups in by_seg.items():
        if len({"Servers" if g == "Identity & naming" else g for g in groups}) >= 3:
            members = sorted(ip for ip in internal if seg(ip) == s)
            out.append(
                Finding(
                    "ZT4",
                    members,
                    [k for k in edges if seg(k[0]) == s and seg(k[1]) == s],
                    f"{s} mixes {', '.join(sorted(groups))} ({len(members)} hosts)",
                )
            )

    for finding in out:
        if finding.check in NEEDS_ANSWER:
            finding.confirmed = all(edges[k].answered is True for k in finding.edges)
    return out
