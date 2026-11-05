"""Explainable host-role inference from flow behaviour.

Each rule adds weighted, graded evidence with a sentence a person can check. LogLM scores
never count as role evidence, so a compromised host is not "learned" as a role; they only
lower the reported confidence. Several roles can hold at once (a DC is usually also DNS);
the top one is primary.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.entity_graph.features import ADMIN_PORTS, Host, Network

# Role -> (label, group) for blocks and colouring.
ROLES = {
    "domain_controller": ("Domain controller", "Identity & naming"),
    "dns": ("DNS server", "Identity & naming"),
    "file_server": ("File server", "Servers"),
    "web_server": ("Web / app server", "Servers"),
    "database": ("Database", "Servers"),
    "mail": ("Mail server", "Servers"),
    "ssh_server": ("Linux / SSH server", "Servers"),
    "admin_workstation": ("Admin / jump host", "Admin"),
    "workstation": ("Workstation", "Workstations"),
    "scanner": ("Scanner / sensor", "Monitoring"),
    "gateway": ("Gateway / router", "Network"),
    "ot_controller": ("OT controller (PLC/RTU)", "OT"),
    "ot_master": ("OT master (HMI/SCADA)", "OT"),
    "cloud_infra": ("Cloud infrastructure", "Infrastructure"),
    "external": ("External", "External"),
    "unknown": ("Unknown", "Unknown"),
}
WEB_PORTS = {80, 443, 8080, 8443, 5000, 8000, 3000}
DB_PORTS = {1433, 1521, 3306, 5432, 27017, 6379, 9200}
MAIL_PORTS = {25, 465, 587, 143, 993, 110, 995}
OT_PORTS = {502, 20000, 44818, 2222, 102, 2404, 47808, 4840}

# Attainable score per role, for coverage. Anything not listed tops out at 4.
MAX_SCORE = {
    "domain_controller": 8,
    "workstation": 5,
    "external": 5,
    "cloud_infra": 5,
}
LIKELY = 0.6
POSSIBLE = 0.35
# Confidence kept when no flow of a host has a byte count. Below LIKELY, so a role read
# from traffic nobody can show was answered never reaches "likely". High enough that a
# host answering Kerberos and LDAP (coverage 5/8) still reads as "possible".
NO_BYTES_FLOOR = 0.58


@dataclass
class Evidence:
    role: str
    weight: float
    grade: float
    text: str

    @property
    def score(self) -> float:
        return self.weight * self.grade


@dataclass
class RoleCandidate:
    role: str
    label: str
    score: float
    evidence: list[str]


@dataclass
class RoleResult:
    primary: str
    confidence: float
    band: str
    candidates: list[RoleCandidate] = field(default_factory=list)
    limits: list[str] = field(default_factory=list)


@dataclass
class RoleContext:
    net: Network
    server_like: set[str] = field(default_factory=set)
    dns_servers: set[str] = field(default_factory=set)
    dcs: set[str] = field(default_factory=set)
    file_servers: set[str] = field(default_factory=set)


def _g(n: float, full: float) -> float:
    return max(0.0, min(1.0, n / full))


def _clients(h: Host, ports: set[int]) -> set[str]:
    out: set[str] = set()
    for p in ports:
        out |= h.served_clients(p)
    return out


def _served_total(h: Host) -> int:
    return sum(len(c) for c in h.served.values())


def _last_octet(entity: str) -> int:
    parts = entity.split(".")
    return int(parts[-1]) if len(parts) == 4 and parts[-1].isdigit() else 0


def evidence_for(h: Host, ctx: RoleContext) -> list[Evidence]:
    ev: list[Evidence] = []

    def add(role: str, weight: float, grade: float, text: str) -> None:
        if grade > 0:
            ev.append(Evidence(role, weight, grade, text))

    if ctx.net.is_metadata(h.ip):
        add("cloud_infra", 5, 1, "link-local / metadata address (169.254.0.0/16)")
        return ev
    if not h.internal:
        add("external", 5, 1, "outside the internal ranges")
        return ev

    # A host that opens far more connections than it receives is a client, even if a few
    # sessions land on its ports; damp service evidence for it. It also needs either no
    # port with a real client base, or a spray of unrelated "served" ports (a server
    # offers a few ports to many clients).
    served_ports = {p for (p, _), c in h.served.items() if c}
    max_clients = max((len(c) for c in h.served.values()), default=0)
    mostly_client = h.flows_out >= 10 * max(h.flows_in, 1) and (
        max_clients < 5 or len(served_ports) >= 6
    )
    undamped = {"admin_workstation", "workstation", "scanner", "gateway"}

    def add_service(role: str, weight: float, grade: float, text: str) -> None:
        if mostly_client and role not in undamped:
            add(role, weight, grade * 0.25, f"{text} (damped: host is mostly a client)")
        else:
            add(role, weight, grade, text)

    kdc, ldap = h.served_clients(88), _clients(h, {389, 636, 3268, 3269})
    if kdc and ldap:
        add_service(
            "domain_controller",
            4,
            _g(min(len(kdc), len(ldap)), 3),
            f"serves Kerberos (88) to {len(kdc)} and LDAP to {len(ldap)} clients",
        )
        for p in (445, 135, 3268, 636):
            n = len(h.served_clients(p))
            add_service(
                "domain_controller", 1, _g(n, 3), f"also serves {p} to {n} clients"
            )
    elif ldap and len(ldap) >= 3:
        add_service(
            "domain_controller",
            2,
            _g(len(ldap), 5),
            f"serves LDAP to {len(ldap)} clients (no Kerberos seen)",
        )
    dns = h.served_clients(53)
    add_service("dns", 4, _g(len(dns), 10), f"answers DNS (53) for {len(dns)} clients")

    smb = h.served_clients(445)
    if not kdc:
        resp = sum(b for (p, _), b in h.served_resp_bytes.items() if p == 445)
        back = f", {resp:,} bytes back" if resp else ""
        add_service(
            "file_server",
            4,
            _g(len(smb), 5),
            f"serves SMB (445) to {len(smb)} clients{back}",
        )
    web = _clients(h, WEB_PORTS)
    add_service(
        "web_server",
        3,
        _g(len(web), 5),
        f"serves HTTP(S)/app ports to {len(web)} clients",
    )
    db = _clients(h, DB_PORTS)
    add_service(
        "database", 4, _g(len(db), 2), f"serves a database port to {len(db)} clients"
    )
    mail = _clients(h, MAIL_PORTS)
    add_service(
        "mail", 4, _g(len(mail), 2), f"serves mail ports to {len(mail)} clients"
    )
    ssh = h.served_clients(22)
    add_service(
        "ssh_server", 2, _g(len(ssh), 3), f"accepts SSH (22) from {len(ssh)} clients"
    )

    # SMB/RPC to a DC or file server is what every domain member does; it only counts as
    # administration when aimed at other hosts.
    routine = ctx.dcs | ctx.file_servers
    admin_targets = {
        s
        for p in ADMIN_PORTS
        for s in h.initiated.get(p, set())
        if s in ctx.server_like and not (p in (135, 445) and s in routine)
    }
    add(
        "admin_workstation",
        4,
        _g(len(admin_targets), 4),
        f"opens admin protocols (SSH/RDP/WinRM/SMB/RPC) to {len(admin_targets)} servers",
    )

    ot_served = _clients(h, OT_PORTS)
    add_service(
        "ot_controller",
        4,
        _g(len(ot_served), 1),
        f"serves an OT protocol to {len(ot_served)} masters",
    )
    ot_init = {s for p in OT_PORTS for s in h.initiated.get(p, set())}
    add(
        "ot_master",
        4,
        _g(len(ot_init), 3),
        f"polls {len(ot_init)} devices over OT protocols",
    )

    # Scanning means many ports, or many internal targets; talking to many internet hosts
    # on 443 is just a cloud agent.
    pairs = len(h.dst_port_pairs)
    internal_peers = {p for p in h.peers_out if ctx.net.is_internal(p)}
    if pairs >= 50 or len(internal_peers) >= 15:
        add(
            "scanner",
            4,
            _g(max(pairs / 200, len(internal_peers) / 20), 1),
            f"reaches {len(internal_peers)} internal hosts on {pairs} host:port pairs",
        )

    external_peers = h.peers_out - internal_peers
    if (
        _served_total(h) <= 2
        and len(external_peers) >= 10
        and h.bytes_out >= 5_000_000
        and h.bytes_out > 5 * max(h.bytes_in, 1)
    ):
        add(
            "scanner",
            3,
            1,
            f"ships {h.bytes_out / 1e6:.1f} MB to {len(external_peers)} internet hosts "
            "and serves nothing: a sensor / log-shipping agent",
        )

    last_octet = _last_octet(h.ip)
    ext_ssh = {c for c in h.served_clients(22) if not ctx.net.is_internal(c)}
    if last_octet in (1, 2, 5, 254) and (ext_ssh or len(h.peers_in) >= 3):
        add(
            "gateway",
            2,
            1,
            f"low/edge address (.{last_octet}) reached from {len(ext_ssh)} external "
            "SSH sources (weak: flows cannot see forwarding)",
        )
        add(
            "gateway",
            2,
            _g(len(external_peers), 10),
            f"talks to {len(external_peers)} internet hosts and serves no internal clients",
        )

    # With no port on any flow, "serves nothing" is unknown rather than observed.
    if (_served_total(h) <= 1 or mostly_client) and h.flows_out and h.flows_with_port:
        uses = [
            name
            for name, entities in (("DNS", ctx.dns_servers), ("a DC", ctx.dcs))
            if h.peers_out & entities
        ]
        add(
            "workstation",
            3,
            1,
            (
                "serves nothing to other hosts; only opens connections"
                if _served_total(h) <= 1
                else f"opens {h.flows_out:,} connections and receives {h.flows_in:,}: a client"
            ),
        )
        if uses:
            add("workstation", 2, 1, f"is a client of {' and '.join(uses)}")
    # An admin/jump host is a workstation that also administers servers: when the admin
    # evidence is solid, the workstation evidence supports it rather than competing.
    if any(e.role == "admin_workstation" and e.grade >= 1.0 for e in ev):
        for e in ev:
            if e.role == "workstation":
                e.role = "admin_workstation"
    return ev


def _limits(h: Host) -> list[str]:
    flows = h.flows_in + h.flows_out
    out: list[str] = []
    if h.flows_with_bytes < flows:
        out.append(
            f"{flows - h.flows_with_bytes} of {flows} flows have no byte counts, so a "
            "service answering cannot be confirmed."
        )
    if h.flows_with_port < flows:
        out.append(
            f"{flows - h.flows_with_port} of {flows} flows have no port, so they say "
            "nothing about what this host serves."
        )
    return out


def infer_roles(hosts: dict[str, Host], net: Network) -> dict[str, RoleResult]:
    # First pass: which hosts serve something (for "admin protocols to servers") and
    # which are DNS/DC, so the workstation rule can refer to them.
    ctx = RoleContext(
        net, server_like={ip for ip, h in hosts.items() if _served_total(h) >= 3}
    )
    first = {ip: evidence_for(h, ctx) for ip, h in hosts.items()}
    ctx.dns_servers = {
        ip
        for ip, ev in first.items()
        if any(e.role == "dns" and e.grade >= 0.5 for e in ev)
    }
    ctx.dcs = {
        ip
        for ip, ev in first.items()
        if any(e.role == "domain_controller" and e.weight >= 4 for e in ev)
    }
    ctx.file_servers = {
        ip
        for ip, ev in first.items()
        if any(e.role == "file_server" and e.grade >= 0.6 for e in ev)
    }

    out: dict[str, RoleResult] = {}
    for ip, h in hosts.items():
        scores: dict[str, float] = {}
        texts: dict[str, list[str]] = {}
        for e in evidence_for(h, ctx):
            scores[e.role] = scores.get(e.role, 0) + e.score
            texts.setdefault(e.role, []).append(f"{e.text} (+{e.score:.1f})")
        limits = _limits(h) if h.internal else []
        if not scores:
            out[ip] = RoleResult("unknown", 0.0, "unknown", limits=limits)
            continue
        ranked = sorted(scores.items(), key=lambda kv: -kv[1])
        top, top_s = ranked[0]
        # Roles that normally come together (a DC is usually the DNS server) do not
        # compete when measuring the margin.
        compatible = {"domain_controller": {"dns"}, "dns": {"domain_controller"}}.get(
            top, set()
        )
        rivals = [sc for r, sc in ranked[1:] if r not in compatible]
        second_s = rivals[0] if rivals else 0.0
        coverage = min(1.0, top_s / MAX_SCORE.get(top, 4))
        margin = (top_s - second_s) / top_s
        flows = h.flows_in + h.flows_out
        visibility = min(1.0, flows / 20)
        byte_share = h.flows_with_bytes / flows if flows else 1.0
        completeness = NO_BYTES_FLOOR + (1 - NO_BYTES_FLOOR) * byte_share
        anomaly_drag = 1 - 0.3 * (h.seq_anomalous / h.seq_total if h.seq_total else 0)
        base = coverage * (0.5 + 0.5 * margin) * (0.6 + 0.4 * visibility) * completeness
        if top in ("external", "cloud_infra"):
            base = 1.0
        # The band comes from traffic evidence alone; LogLM anomalies only shade the
        # reported confidence, so an attack never relabels a host "unknown".
        band = (
            "likely"
            if base >= LIKELY
            else "possible" if base >= POSSIBLE else "unknown"
        )
        candidates = [
            RoleCandidate(r, ROLES[r][0], round(s, 2), texts[r])
            for r, s in ranked
            if s >= 0.4 * top_s
        ]
        out[ip] = RoleResult(
            top if band != "unknown" else "unknown",
            round(base * anomaly_drag, 3),
            band,
            candidates,
            limits,
        )
    return out
