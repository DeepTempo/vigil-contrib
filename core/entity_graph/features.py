"""Stored log events to flows, then flows to per-host features and per-pair edges.

A flow is one log event naming a source and a destination. The columns carry the two
ends, the destination port, the action and LogLM's score. Source port, protocol and byte
counts come from the source's own record when it holds them. Whatever a flow lacks stays
``None``, and the role and zero-trust layers say what that cost them.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from core.storage.ip_address import normalize_ip

# Service ports trusted to mark the responder even without a SYN (incl. OT).
WELL_KNOWN = {
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    88,
    110,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    389,
    443,
    445,
    464,
    465,
    500,
    502,
    514,
    515,
    587,
    631,
    636,
    993,
    995,
    1433,
    1521,
    1883,
    2222,
    2404,
    3268,
    3269,
    3306,
    3389,
    4500,
    4840,
    5000,
    5432,
    5985,
    5986,
    6379,
    7000,
    8000,
    8080,
    8443,
    9100,
    9200,
    20000,
    27017,
    44818,
    47808,
}
ADMIN_PORTS = {22, 135, 445, 3389, 5985, 5986}
# The score the console already draws as hot (LoglmMeter).
LOGLM_ANOMALOUS = 0.7

DEFAULT_INTERNAL = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    # Documentation ranges never appear on a real network, and Vigil's own samples use
    # these two as internal. 203.0.113.0/24 stays outside, as those samples use it.
    "192.0.2.0/24",
    "198.51.100.0/24",
)
LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
INTERNAL_NAME_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home.arpa")
INTERNET = "internet"
METADATA = str(LINK_LOCAL)
NAMED = "named"

# Keys that hold each field in a source's own record, most specific first.
RAW_FIELDS = {
    "src_port": (
        "src_port",
        "source_port",
        "Source Port",
        "sport",
        "srcport",
        "spt",
        "id.orig_p",
    ),
    "proto": ("proto", "protocol", "transport", "ip_proto", "IP Protocol"),
    "bytes_fwd": (
        "fwd_bytes",
        "orig_bytes",
        "bytes_out",
        "bytes_sent",
        "Bytes Sent",
        "sent_bytes",
        "out_bytes",
    ),
    "bytes_bwd": (
        "bwd_bytes",
        "resp_bytes",
        "bytes_in",
        "bytes_received",
        "Bytes Received",
        "received_bytes",
        "in_bytes",
    ),
}
PROTO_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "6.0": "tcp", "17.0": "udp"}
UNANSWERED_ACTIONS = {
    "no_reply",
    "deny",
    "denied",
    "drop",
    "dropped",
    "block",
    "blocked",
    "reject",
    "rejected",
}
NOT_A_HOST = {"-", "unknown", "n/a", "none", "null", "localhost"}


def _address(entity: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(entity)
    except ValueError:
        return None


@dataclass(frozen=True)
class Network:
    """Which entities count as inside, and which segment each one sits in."""

    internal: tuple = ()

    @classmethod
    def of(cls, cidrs: Iterable[str] = DEFAULT_INTERNAL) -> "Network":
        return cls(tuple(ipaddress.ip_network(c, strict=False) for c in cidrs))

    def is_internal(self, entity: str) -> bool:
        address = _address(entity)
        if address is None:
            return "." not in entity or entity.endswith(INTERNAL_NAME_SUFFIXES)
        return any(address in n for n in self.internal)

    def is_metadata(self, entity: str) -> bool:
        address = _address(entity)
        return address is not None and address in LINK_LOCAL

    def subnet_of(self, entity: str) -> str:
        address = _address(entity)
        if address is None:
            return NAMED if self.is_internal(entity) else INTERNET
        if address in LINK_LOCAL:
            return METADATA
        if not self.is_internal(entity):
            return INTERNET
        prefix = 24 if address.version == 4 else 64
        return str(ipaddress.ip_network(f"{entity}/{prefix}", strict=False))


@dataclass(frozen=True)
class Flow:
    src: str
    dst: str
    time: float
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: str = ""
    bytes_fwd: Optional[int] = None
    bytes_bwd: Optional[int] = None
    loglm: Optional[float] = None


@dataclass
class FlowSet:
    """Flows read from rows. ``aliases`` maps a hostname to the address it was seen with."""

    flows: list[Flow] = field(default_factory=list)
    names: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    skipped: int = 0


def _count(value: Any) -> Optional[int]:
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return number if number >= 0 else None


def _port(value: Any) -> Optional[int]:
    number = _count(value)
    return number if number is not None and 1 <= number <= 65535 else None


def usable_address(value: Any) -> Optional[str]:
    """A canonical address that names one machine. Loopback means a different box on
    every row, so drawing it would link hosts that never spoke."""
    canonical = normalize_ip(value)
    if canonical is None:
        return None
    address = ipaddress.ip_address(canonical)
    return None if address.is_loopback or address.is_unspecified else canonical


def usable_name(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    name = value.strip().lower()
    if not name or name in NOT_A_HOST or normalize_ip(name):
        return None
    return name


def _endpoint(ip: Any, host: Any, aliases: Mapping[str, str]) -> Optional[str]:
    address = usable_address(ip) or usable_address(host)
    if address:
        return address
    name = usable_name(host)
    return aliases.get(name, name) if name else None


def _raw_value(raw: Mapping[str, Any], field_name: str) -> Any:
    for key in RAW_FIELDS[field_name]:
        value = raw.get(key)
        if value not in (None, ""):
            return value
    return None


def _score(value: Any) -> Optional[float]:
    return float(value) if value is not None and 0 <= value <= 1 else None


def flows_from_rows(rows: Iterable[Mapping[str, Any]]) -> FlowSet:
    """Rows with ``time``, ``src_*``/``dst_*``, ``event_class``, ``action``, ``loglm`` and ``raw``.

    A row with no second end, or the same machine on both ends, is counted in ``skipped``.
    """
    rows = list(rows)
    out = FlowSet()
    for row in rows:
        for ip_key, host_key in (("src_ip", "src_host"), ("dst_ip", "dst_host")):
            # A DNS row's dst_host is the name asked about, not the resolver's own.
            if host_key == "dst_host" and row.get("event_class") == "DNS":
                continue
            address, name = usable_address(row.get(ip_key)), row.get(host_key)
            if address and usable_name(name):
                out.names.setdefault(address, name.strip())
                out.aliases.setdefault(usable_name(name), address)

    for row in rows:
        src = _endpoint(row.get("src_ip"), row.get("src_host"), out.aliases)
        dst = _endpoint(row.get("dst_ip"), row.get("dst_host"), out.aliases)
        if not src or not dst or src == dst:
            out.skipped += 1
            continue
        raw = row.get("raw") or {}
        proto = str(_raw_value(raw, "proto") or "").lower()
        bytes_bwd = _count(_raw_value(raw, "bytes_bwd"))
        if (
            bytes_bwd is None
            and str(row.get("action") or "").lower() in UNANSWERED_ACTIONS
        ):
            bytes_bwd = 0
        out.flows.append(
            Flow(
                src=src,
                dst=dst,
                time=row["time"].timestamp(),
                src_port=_port(_raw_value(raw, "src_port")),
                dst_port=_port(row.get("dst_port")),
                proto=PROTO_NUMBERS.get(proto, proto),
                bytes_fwd=_count(_raw_value(raw, "bytes_fwd")),
                bytes_bwd=bytes_bwd,
                loglm=_score(row.get("loglm")),
            )
        )
    return out


@dataclass
class Host:
    ip: str
    internal: bool
    flows_in: int = 0
    flows_out: int = 0
    flows_with_port: int = 0
    flows_with_bytes: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    # port/proto served -> client entities, and bytes the server sent back
    served: dict[tuple[int, str], set[str]] = field(
        default_factory=lambda: defaultdict(set)
    )
    served_resp_bytes: dict[tuple[int, str], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    # as a client: dst port -> server entities
    initiated: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    peers_out: set[str] = field(default_factory=set)
    peers_in: set[str] = field(default_factory=set)
    dst_port_pairs: set[tuple[str, int]] = field(default_factory=set)
    seq_total: int = 0
    seq_anomalous: int = 0
    max_anomaly_conf: float = 0.0

    def served_clients(self, port: int, proto: Optional[str] = None) -> set[str]:
        out: set[str] = set()
        for (p, pr), clients in self.served.items():
            if p == port and (proto is None or pr == proto):
                out |= clients
        return out


@dataclass
class Edge:
    src: str  # client / initiator
    dst: str  # server / responder
    flows: int = 0
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    flows_with_bytes: int = 0
    answer_unknown: int = 0
    services: dict[tuple[int, str], int] = field(
        default_factory=lambda: defaultdict(int)
    )
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    starts: list[float] = field(default_factory=list)  # for periodicity
    seq_total: int = 0
    seq_anomalous: int = 0
    max_anomaly_conf: float = 0.0

    @property
    def answered(self) -> Optional[bool]:
        """True when bytes came back, False when none did, None when no count says."""
        if self.bytes_bwd > 0:
            return True
        return None if self.answer_unknown else False


def _orient(flow: Flow) -> tuple[str, str, Optional[int], Optional[int]]:
    """(client, server, client_port, server_port). The flow's source is the originator
    unless the ports say the record is a reply. Only trust that from a privileged source
    port, or a service port answering into the ephemeral range: clients pick random
    source ports, and one landing on 1521 or 9200 is not a database. With no source port
    there is nothing to read, so the row's direction stands."""
    s, d, sp, dp = flow.src, flow.dst, flow.src_port, flow.dst_port
    if sp is not None and dp is not None:
        if (sp < 1024 and dp >= 1024 and dp not in WELL_KNOWN) or (
            sp in WELL_KNOWN and dp >= 49152
        ):
            return d, s, dp, sp
    return s, d, sp, dp


def build_graph(
    flows: Iterable[Flow], net: Network
) -> tuple[dict[str, Host], dict[tuple[str, str], Edge]]:
    hosts: dict[str, Host] = {}
    edges: dict[tuple[str, str], Edge] = {}

    def host(entity: str) -> Host:
        if entity not in hosts:
            hosts[entity] = Host(entity, net.is_internal(entity))
        return hosts[entity]

    for flow in flows:
        client, server, _, sport = _orient(flow)
        fwd, bwd = flow.bytes_fwd, flow.bytes_bwd
        if client != flow.src:
            fwd, bwd = bwd, fwd
        c, s = host(client), host(server)
        e = edges.setdefault((client, server), Edge(client, server))
        c.flows_out += 1
        s.flows_in += 1
        c.peers_out.add(server)
        s.peers_in.add(client)
        c.bytes_out += fwd or 0
        s.bytes_in += fwd or 0
        c.bytes_in += bwd or 0
        s.bytes_out += bwd or 0
        e.flows += 1
        e.bytes_fwd += fwd or 0
        e.bytes_bwd += bwd or 0
        if bwd is None:
            e.answer_unknown += 1
        else:
            e.flows_with_bytes += 1
            c.flows_with_bytes += 1
            s.flows_with_bytes += 1
        if sport is not None:
            c.flows_with_port += 1
            s.flows_with_port += 1
            c.dst_port_pairs.add((server, sport))
            c.initiated[sport].add(server)
            e.services[(sport, flow.proto)] += 1
            # A port counts as served when the server answered, so a scan's one-packet
            # SYNs do not make every scanned port a service. With no count either way
            # the port stays possible, and the confidence model says so.
            if bwd is None or bwd > 0:
                s.served[(sport, flow.proto)].add(client)
                s.served_resp_bytes[(sport, flow.proto)] += bwd or 0
        if len(e.starts) < 2000:
            e.starts.append(flow.time)
        e.first_ts = flow.time if e.first_ts is None else min(e.first_ts, flow.time)
        e.last_ts = flow.time if e.last_ts is None else max(e.last_ts, flow.time)
        if flow.loglm is not None:
            anomalous = flow.loglm >= LOGLM_ANOMALOUS
            for scored in (c, s, e):
                scored.seq_total += 1
                scored.seq_anomalous += anomalous
                scored.max_anomaly_conf = max(scored.max_anomaly_conf, flow.loglm)
    return hosts, edges
