#!/usr/bin/env python3
"""A test double for local proof: enough of Elasticsearch and Kibana to read the sample.

It is not Elasticsearch. It speaks what the real Elastic federation adapter and
``core/integrations/credential_check.py`` call, and serves the bundled sample history as
Kibana detection alerts with its times shifted to end just before now. Point the
elastic-siem integration's ``elasticsearch_url`` and ``kibana_url`` at it.

    PYTHONPATH=. python3 scripts/coldstart/fake_elastic.py --port 9200
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional

from core.coldstart.baseline import parse_time
from core.coldstart.sample_history import load_sample

# Past the adapter's 60-second settle delay, or the newest alerts would not be
# readable yet when a run starts.
_NEWEST_ALERT_AGE = timedelta(minutes=2)


def _first(values: Any) -> Optional[str]:
    return values[0] if values else None


def alert_document(alert: Mapping[str, Any]) -> Dict[str, Any]:
    """The sample alert as a Kibana detection alert hit. ECS fields hold one value,
    so an alert with two users or addresses keeps the first."""
    iocs = alert.get("iocs") or {}
    source: Dict[str, Any] = {
        "@timestamp": alert["timestamp"],
        "kibana.alert.rule.name": alert["title"],
        "kibana.alert.rule.description": alert.get("description", ""),
        "kibana.alert.severity": alert["severity"],
    }
    for field, key, sub in (
        ("source", "src_ips", "ip"),
        ("destination", "dst_ips", "ip"),
        ("host", "hostnames", "name"),
        ("user", "usernames", "name"),
    ):
        value = _first(iocs.get(key))
        if value:
            source[field] = {sub: value}
    return {
        "_id": alert["external_id"],
        "_index": ".alerts-security.alerts-default",
        "_source": source,
    }


def _field(document: Mapping[str, Any], path: str) -> Any:
    source = document["_source"]
    if path in source:
        return source[path]
    value: Any = source
    for part in path.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def _in_range(value: Any, bounds: Mapping[str, Any]) -> bool:
    """A document without the field does not match, as in Elasticsearch."""
    if value is None:
        return False
    if isinstance(value, str):
        when = parse_time(value)
        gte, lte = parse_time(bounds.get("gte")), parse_time(bounds.get("lte"))
        return (gte is None or when >= gte) and (lte is None or when <= lte)
    return value >= bounds.get("gte", value) and value <= bounds.get("lte", value)


def search(documents: List[Dict[str, Any]], body: Mapping[str, Any]) -> Dict[str, Any]:
    """The range filters and @timestamp sort the adapter sends. Sort ties keep document
    order, as ``_doc`` does."""
    filters = ((body.get("query") or {}).get("bool") or {}).get("filter") or []
    ranges = [item["range"] for item in filters if "range" in item]
    matched = [
        document
        for document in documents
        if all(
            _in_range(_field(document, field), bounds)
            for spec in ranges
            for field, bounds in spec.items()
        )
    ]
    order = next(
        (s["@timestamp"]["order"] for s in body.get("sort") or [] if "@timestamp" in s),
        "asc",
    )
    matched.sort(
        key=lambda d: parse_time(d["_source"]["@timestamp"]), reverse=order == "desc"
    )
    size = body.get("size", 10)
    return {
        "took": 1,
        "timed_out": False,
        "hits": {
            "total": {"value": len(matched), "relation": "eq"},
            "hits": matched[:size],
        },
    }


def make_server(
    port: int = 0, now: Optional[datetime] = None, host: str = "127.0.0.1"
) -> ThreadingHTTPServer:
    start = now or datetime.now(timezone.utc)
    alerts, _ = load_sample(start - _NEWEST_ALERT_AGE)
    documents = [alert_document(alert) for alert in alerts]

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/":
                self._send(
                    200,
                    {
                        "cluster_name": "fake-elastic-test-double",
                        "version": {"number": "8.13.0"},
                    },
                )
            elif self.path == "/api/status":
                self._send(200, {"version": {"number": "8.13.0"}})
            else:
                self._send(404, {"error": f"not served: {self.path}"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/_test/alerts":
                # Lets a local proof make a new alert arrive after going live.
                documents.append(
                    alert_document(
                        {
                            **body,
                            "external_id": body.get("external_id") or uuid.uuid4().hex,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                )
                self._send(200, {"result": "created"})
            elif (
                self.path == "/api/detection_engine/signals/search"
                or self.path.endswith("/_search")
            ):
                self._send(200, search(documents, body))
            else:
                self._send(404, {"error": f"not served: {self.path}"})

        def log_message(self, format: str, *args: Any) -> None:
            pass

    return ThreadingHTTPServer((host, port), Handler)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9200)
    args = parser.parse_args()
    server = make_server(args.port)
    print(f"Fake Elasticsearch test double on http://127.0.0.1:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
