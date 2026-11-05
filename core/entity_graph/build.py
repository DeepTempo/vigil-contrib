"""The entity graph: hosts with inferred roles, blocks, edges with LogLM's overlay,
zero-trust findings with the flows behind them, and one case's path across it.
"""

from __future__ import annotations

import os.path
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from core.entity_graph.features import (
    INTERNET,
    METADATA,
    NAMED,
    Edge,
    Flow,
    FlowSet,
    Host,
    Network,
    build_graph,
    usable_address,
    usable_name,
)
from core.entity_graph.roles import ROLES, RoleCandidate, infer_roles
from core.entity_graph.zerotrust import (
    CHECKS,
    NEEDS_BYTES,
    NEEDS_LOGLM,
    NEEDS_PORTS,
    Finding,
    run_checks,
)
from core.storage.ip_address import FINDING_IP_KEYS

EDGE_CAP = 5000
FLOWS_PER_FINDING = 25
QUERY_TERMS_CAP = 20
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
ZONE_NAMES = {INTERNET: "Internet", METADATA: "Cloud metadata", NAMED: "Named hosts"}
HOST_KEYS = (
    "hostname",
    "hostnames",
    "host",
    "src_host",
    "dst_host",
    "domain",
    "domains",
)


@dataclass
class LoglmStats:
    scored: int
    anomalous: int
    max_score: Optional[float]


@dataclass
class NodeRole:
    primary: str
    label: str
    group: str
    confidence: float
    band: str
    candidates: list[RoleCandidate]
    limits: list[str]


@dataclass
class ServedPort:
    port: int
    proto: str
    clients: int


@dataclass
class NodeStats:
    flows_in: int
    flows_out: int
    bytes_in: Optional[int]
    bytes_out: Optional[int]
    served_ports: list[ServedPort]


@dataclass
class GraphNode:
    id: str
    label: str
    hostname: Optional[str]
    internal: bool
    subnet: str
    block: str
    role: NodeRole
    stats: NodeStats
    loglm: LoglmStats
    findings: list[str]
    on_path: bool
    logs_query: str


@dataclass
class Service:
    port: int
    proto: str
    flows: int


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    flows: int
    bytes: Optional[int]
    answered: Optional[bool]
    services: list[Service]
    first_ts: Optional[float]
    last_ts: Optional[float]
    cross_block: bool
    cross_subnet: bool
    loglm: LoglmStats
    findings: list[str]
    on_path: bool


@dataclass
class Block:
    id: str
    subnet: str
    zone: str
    group: str
    label: str
    hosts: list[str]
    roles: dict[str, int]
    anomalous_hosts: int
    findings: list[str]


@dataclass
class FindingFlow:
    source: str
    target: str
    flows: int
    ports: list[int]
    first_ts: Optional[float]
    last_ts: Optional[float]


@dataclass
class ZeroTrustFinding:
    id: str
    check: str
    title: str
    severity: str
    detail: str
    why: str
    false_positive_note: str
    confirmed: bool
    hosts: list[str]
    flows: list[FindingFlow]
    flows_total: int
    logs_query: str


@dataclass
class PathHop:
    source: str
    target: str
    flows: int
    first_ts: Optional[float]
    last_ts: Optional[float]


@dataclass
class CasePath:
    case_id: str
    title: str
    entities: list[str]
    not_seen: list[str]
    hops: list[PathHop]


@dataclass
class CaseRef:
    case_id: str
    title: str
    entities: list[str] = field(default_factory=list)


@dataclass
class Coverage:
    flows: int
    with_port: int
    with_source_port: int
    with_bytes: int
    scored: int


@dataclass
class CheckNotRun:
    check: str
    title: str
    needs: str


@dataclass
class Truncated:
    nodes: int = 0
    edges: int = 0


@dataclass
class EntityGraph:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    blocks: list[Block]
    findings: list[ZeroTrustFinding]
    coverage: Coverage
    checks_not_run: list[CheckNotRun]
    truncated: Truncated
    loglm: bool
    path: Optional[CasePath]


def entities_of_contexts(contexts: Iterable[Optional[Mapping[str, Any]]]) -> list[str]:
    """Every address and hostname a finding's entity context names, in a stable order."""
    found: set[str] = set()
    for context in contexts:
        for key, value in (context or {}).items():
            if key not in FINDING_IP_KEYS and key not in HOST_KEYS:
                continue
            for item in value if isinstance(value, list) else [value]:
                entity = usable_address(item) or usable_name(item)
                if entity:
                    found.add(entity)
    return sorted(found)


def _logs_term(values: list[str]) -> str:
    key = "ip" if usable_address(values[0]) else "host"
    return f"{key}:{','.join(values)}"


def _one_kind(values: list[str]) -> bool:
    return len({bool(usable_address(v)) for v in values}) == 1


def logs_query(pairs: list[tuple[str, str]], ports: list[int]) -> str:
    """The Logs search for a finding's flows: both ends of each pair, on its ports. A term
    is AND, values in a term are OR, and an address ending in a dot is a prefix."""
    ends = sorted({x for pair in pairs for x in pair})
    shared = [x for x in ends if all(x in pair for pair in pairs)]
    if len(pairs) == 1:
        terms = [_logs_term([x]) for x in pairs[0]]
    elif shared:
        hub = shared[0]
        others = [x for x in ends if x != hub]
        fits = len(others) <= QUERY_TERMS_CAP and _one_kind(others)
        terms = [_logs_term([hub]), _logs_term(others)] if fits else [_logs_term([hub])]
    elif len(ends) <= QUERY_TERMS_CAP and _one_kind(ends):
        terms = [_logs_term(ends)]
    else:
        prefix = os.path.commonprefix(ends)
        prefix = prefix[: prefix.rfind(".") + 1]
        terms = (
            [f"ip:{prefix}"] if prefix.count(".") == 3 else [_logs_term(list(pairs[0]))]
        )
    if ports:
        terms.append(f"port:{','.join(map(str, ports))}")
    return " ".join(terms)


def _loglm(subject: Host | Edge) -> LoglmStats:
    return LoglmStats(
        subject.seq_total,
        subject.seq_anomalous,
        round(subject.max_anomaly_conf, 3) if subject.seq_total else None,
    )


def _finding_flows(
    finding: Finding, edges: dict[tuple[str, str], Edge]
) -> list[FindingFlow]:
    def flows_on_ports(e: Edge) -> int:
        if not finding.ports:
            return e.flows
        return sum(n for (p, _), n in e.services.items() if p in finding.ports)

    rows = [
        FindingFlow(
            a,
            b,
            flows_on_ports(edges[(a, b)]),
            sorted(
                {p for (p, _) in edges[(a, b)].services}
                & (set(finding.ports) or {p for (p, _) in edges[(a, b)].services})
            ),
            edges[(a, b)].first_ts,
            edges[(a, b)].last_ts,
        )
        for a, b in finding.edges
    ]
    return sorted(rows, key=lambda r: -r.flows)


def _coverage(flows: list[Flow]) -> Coverage:
    return Coverage(
        flows=len(flows),
        with_port=sum(f.dst_port is not None for f in flows),
        with_source_port=sum(f.src_port is not None for f in flows),
        with_bytes=sum(f.bytes_bwd is not None for f in flows),
        scored=sum(f.loglm is not None for f in flows),
    )


def _checks_not_run(coverage: Coverage) -> list[CheckNotRun]:
    if not coverage.flows:
        return []
    needs = [
        (coverage.with_port, NEEDS_PORTS, "destination ports"),
        (coverage.with_bytes, NEEDS_BYTES, "byte counts"),
        (coverage.scored, NEEDS_LOGLM, "LogLM scores"),
    ]
    return [
        CheckNotRun(check, CHECKS[check][0], need)
        for have, checks, need in needs
        if not have
        for check in checks
    ]


def _case_path(
    case: CaseRef,
    flowset: FlowSet,
    hosts: dict[str, Host],
    edges: dict[tuple[str, str], Edge],
) -> tuple[CasePath, set[str]]:
    resolved = {name: flowset.aliases.get(name, name) for name in case.entities}
    in_graph = {node for node in resolved.values() if node in hosts}
    on_path = sorted(
        (e for (a, b), e in edges.items() if a in in_graph and b in in_graph),
        key=lambda e: (e.first_ts or 0, e.src, e.dst),
    )
    path = CasePath(
        case_id=case.case_id,
        title=case.title,
        entities=sorted(in_graph),
        not_seen=sorted(name for name, node in resolved.items() if node not in hosts),
        hops=[PathHop(e.src, e.dst, e.flows, e.first_ts, e.last_ts) for e in on_path],
    )
    return path, in_graph


def build(
    flowset: FlowSet,
    net: Network,
    case: Optional[CaseRef] = None,
    max_edges: int = EDGE_CAP,
) -> EntityGraph:
    hosts, edges = build_graph(flowset.flows, net)
    roles = infer_roles(hosts, net)
    raw_findings = sorted(
        run_checks(hosts, edges, roles, net),
        key=lambda f: (-SEVERITY_RANK[f.severity], f.check),
    )
    path, path_nodes = (
        _case_path(case, flowset, hosts, edges) if case else (None, set())
    )

    def block_of(entity: str) -> str:
        subnet = net.subnet_of(entity)
        if subnet in (INTERNET, METADATA):
            return subnet
        return f"{subnet}|{ROLES[roles[entity].primary][1]}"

    host_findings: dict[str, list[str]] = defaultdict(list)
    edge_findings: dict[str, list[str]] = defaultdict(list)
    findings: list[ZeroTrustFinding] = []
    for i, f in enumerate(raw_findings, 1):
        fid = f"{f.check}-{i}"
        flows = _finding_flows(f, edges)
        for h in f.hosts:
            host_findings[h].append(fid)
        for a, b in f.edges:
            edge_findings[f"{a}->{b}"].append(fid)
        findings.append(
            ZeroTrustFinding(
                id=fid,
                check=f.check,
                title=f.title,
                severity=f.severity,
                detail=f.detail,
                why=f.why,
                false_positive_note=f.false_positive_note,
                confirmed=f.confirmed,
                hosts=f.hosts,
                flows=flows[:FLOWS_PER_FINDING],
                flows_total=len(flows),
                logs_query=(
                    logs_query(list(f.edges), f.ports)
                    if f.edges
                    else _logs_term([f.hosts[0]])
                ),
            )
        )

    graph_edges = [
        GraphEdge(
            id=f"{a}->{b}",
            source=a,
            target=b,
            flows=e.flows,
            bytes=e.bytes_fwd + e.bytes_bwd if e.flows_with_bytes else None,
            answered=e.answered,
            services=sorted(
                (Service(p, pr, n) for (p, pr), n in e.services.items()),
                key=lambda s: -s.flows,
            )[:10],
            first_ts=e.first_ts,
            last_ts=e.last_ts,
            cross_block=block_of(a) != block_of(b),
            cross_subnet=net.subnet_of(a) != net.subnet_of(b),
            loglm=_loglm(e),
            findings=edge_findings.get(f"{a}->{b}", []),
            on_path=a in path_nodes and b in path_nodes,
        )
        for (a, b), e in edges.items()
    ]
    kept_edges = sorted(
        graph_edges, key=lambda e: (not (e.on_path or e.findings), -e.flows, e.id)
    )[:max_edges]
    linked = {x for e in kept_edges for x in (e.source, e.target)}
    kept_hosts = {
        entity
        for entity in hosts
        if entity in linked or entity in path_nodes or entity in host_findings
    }

    nodes = []
    for entity in sorted(kept_hosts):
        h, r = hosts[entity], roles[entity]
        label, group = ROLES[r.primary]
        hostname = flowset.names.get(entity)
        served = sorted(
            (ServedPort(p, pr, len(c)) for (p, pr), c in h.served.items()),
            key=lambda s: -s.clients,
        )[:12]
        nodes.append(
            GraphNode(
                id=entity,
                label=hostname or entity,
                hostname=hostname,
                internal=h.internal,
                subnet=net.subnet_of(entity),
                block=block_of(entity),
                role=NodeRole(
                    r.primary,
                    label,
                    group,
                    r.confidence,
                    r.band,
                    r.candidates,
                    r.limits,
                ),
                stats=NodeStats(
                    h.flows_in,
                    h.flows_out,
                    h.bytes_in if h.flows_with_bytes else None,
                    h.bytes_out if h.flows_with_bytes else None,
                    served,
                ),
                loglm=_loglm(h),
                findings=host_findings.get(entity, []),
                on_path=entity in path_nodes,
                logs_query=_logs_term([entity]),
            )
        )

    blocks: dict[str, Block] = {}
    roles_in_block: dict[str, Counter] = defaultdict(Counter)
    for n in nodes:
        b = blocks.get(n.block)
        if b is None:
            zone = ZONE_NAMES.get(n.subnet, n.subnet)
            b = blocks[n.block] = Block(
                id=n.block,
                subnet=n.subnet,
                zone=zone,
                group=n.role.group,
                label=f"{zone} · {n.role.group}" if "|" in n.block else zone,
                hosts=[],
                roles={},
                anomalous_hosts=0,
                findings=[],
            )
        b.hosts.append(n.id)
        roles_in_block[n.block][n.role.label] += 1
        b.anomalous_hosts += bool(n.loglm.anomalous)
        b.findings = sorted({*b.findings, *n.findings})
    for block_id, counts in roles_in_block.items():
        blocks[block_id].roles = dict(counts)

    coverage = _coverage(flowset.flows)
    return EntityGraph(
        nodes=nodes,
        edges=kept_edges,
        blocks=list(blocks.values()),
        findings=findings,
        coverage=coverage,
        checks_not_run=_checks_not_run(coverage),
        truncated=Truncated(
            len(hosts) - len(nodes), len(graph_edges) - len(kept_edges)
        ),
        loglm=coverage.scored > 0,
        path=path,
    )
