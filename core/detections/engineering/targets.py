"""Sigma to SIEM conversion over whichever pySigma backends are installed, per target.

Ported from the detection write-back tool. pySigma is optional and not in requirements.lock
(see requirements-sigma.txt), so every target can answer "not installed". A failure on one
target never hides the others. Conversion only produces text: nothing here reaches a SIEM.

``measured_valid_pct`` is the tool's eval, 3,763 public SigmaHQ rules on 2026-10-21 with
pySigma 0.11.23: the share whose packaged file was well-formed. No SIEM was available, so valid
does not mean it runs: field names, tables and log types were not checked against a schema.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, List, Literal, Optional, Tuple

from core.detections.engineering import package

PYSIGMA_MISSING = (
    "pySigma is not installed. It is optional and not in requirements.lock; install "
    "core/detections/engineering/requirements-sigma.txt, or paste a query here."
)

TargetStatus = Literal[
    "converted", "pasted", "needs_field_mapping", "not_installed", "failed"
]


@dataclass(frozen=True)
class Target:
    name: str
    platform: str
    backend: str
    format: str
    pipelines: Tuple[Tuple[str, ...], ...]
    ext: str
    measured_valid_pct: float
    # The format that yields the bare query, for a target the overlay can hold.
    query_format: Optional[str] = None


TARGETS: Dict[str, Target] = {
    t.name: t
    for t in (
        Target(
            "splunk",
            "Splunk",
            "splunk",
            "savedsearches",
            (("splunk_windows",), ("splunk_cim",)),
            "conf",
            99.8,
            "default",
        ),
        Target(
            "sentinel",
            "Microsoft Sentinel",
            "kusto",
            "default",
            (("sentinel_asim",), ("azure_monitor",)),
            "yaml",
            46.2,
        ),
        Target(
            "defender",
            "Microsoft Defender XDR",
            "kusto",
            "default",
            (("microsoft_xdr",), ("microsoft_365_defender",)),
            "kql",
            61.7,
        ),
        Target(
            "panther", "Panther", "panther", "sdyaml", ((), ("panther",)), "yml", 91.8
        ),
        Target(
            "elastic",
            "Elastic Security (ES|QL)",
            "esql",
            "siem_rule_ndjson",
            (("ecs_windows",), ("ecs_zeek_beats",), ("ecs_kubernetes",)),
            "ndjson",
            97.1,
            "default",
        ),
        Target(
            "elastic-lucene",
            "Elastic Security (Lucene)",
            "lucene",
            "default",
            (("ecs_windows",), ("ecs_zeek_beats",), ("ecs_kubernetes",)),
            "lucene",
            99.8,
            "default",
        ),
        Target(
            "opensearch",
            "OpenSearch",
            "opensearch_lucene",
            "monitor_rule",
            (("ecs_windows",), ("ecs_zeek_beats",)),
            "json",
            99.8,
        ),
        Target(
            "chronicle",
            "Google SecOps",
            "secops",
            "yara_l",
            (("secops_udm",),),
            "yaral",
            62.0,
        ),
        Target(
            "qradar",
            "IBM QRadar",
            "q_radar_aql",
            "default",
            (("qradar-aql-fields",), ("qradar-aql-payload",)),
            "aql",
            96.7,
        ),
        Target(
            "crowdstrike",
            "CrowdStrike LogScale",
            "log_scale",
            "default",
            (("crowdstrike_falcon",), ("crowdstrike_fdr",)),
            "logscale",
            90.6,
        ),
        Target(
            "sentinelone",
            "SentinelOne PowerQuery",
            "sentinel_one_pq",
            "default",
            ((), ("sentinelonepq",)),
            "pq",
            43.7,
        ),
        Target(
            "datadog",
            "Datadog Cloud SIEM",
            "datadog",
            "default",
            ((), ("datadog",)),
            "txt",
            96.7,
        ),
        Target("loki", "Grafana Loki", "loki", "ruler", ((),), "yml", 99.7),
    )
}
_PASTABLE = {"splunk": "splunk", "elastic": "elastic-lucene"}


@lru_cache(maxsize=1)
def _plugins() -> Any:
    from sigma.plugins import InstalledSigmaPlugins

    return InstalledSigmaPlugins.autodiscover()


def pysigma_installed() -> bool:
    try:
        import sigma.collection  # noqa: F401
    except ImportError:
        return False
    return True


def sigma_error(text: str) -> Optional[str]:
    """What pySigma says is wrong with ``text``: None when nothing, PYSIGMA_MISSING without it."""
    if not pysigma_installed():
        return PYSIGMA_MISSING
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError

    try:
        errors = SigmaCollection.from_yaml(text, collect_errors=True).errors
    except (SigmaError, ValueError, TypeError) as exc:
        return str(exc)
    return "; ".join(str(e) for e in errors) or None


def availability() -> List[Dict[str, Any]]:
    """Each target, whether it can convert here, and its measured rate."""
    installed = dict(_plugins().backends) if pysigma_installed() else {}
    return [
        {
            "target": t.name,
            "platform": t.platform,
            "installed": t.backend in installed,
            "measured_valid_pct": t.measured_valid_pct,
        }
        for t in TARGETS.values()
    ]


def _render(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        return "\n".join(_render(o) for o in output)
    if isinstance(output, dict):
        return json.dumps(output, indent=2)
    return str(output)


def _row(target: Target, status: TargetStatus, **rest: Any) -> Dict[str, Any]:
    return {
        "target": target.name,
        "platform": target.platform,
        "status": status,
        "measured_valid_pct": target.measured_valid_pct,
        "pipeline": [],
        "tried": [],
        "output": "",
        "file": None,
        "query": None,
        "error": "",
        **rest,
    }


def _mapping_gap(error_type: str) -> bool:
    # The field or log source has no mapping in the pipeline; the rule itself is fine.
    return error_type == "SigmaTransformationError"


def _convert_one(text: str, doc: Dict[str, Any], target: Target) -> Dict[str, Any]:
    from sigma.collection import SigmaCollection
    from sigma.processing.resolver import ProcessingPipelineResolver

    backend_cls = _plugins().backends.get(target.backend)
    if backend_cls is None:
        return _row(
            target,
            "not_installed",
            error=f"The pySigma backend {target.backend!r} is not installed.",
        )
    resolver = ProcessingPipelineResolver(_plugins().pipelines)
    needs_pipeline = bool(getattr(backend_cls, "requires_pipeline", False))
    tried: List[str] = []
    errors: List[Tuple[str, str]] = []
    for pipes in target.pipelines:
        label = "+".join(pipes) or "(none)"
        if not pipes and needs_pipeline:
            continue
        tried.append(label)
        try:
            # A pipeline rewrites the rule it is given, so each conversion gets its own copy.
            def run(fmt: str) -> Any:
                pipeline = resolver.resolve(list(pipes)) if pipes else None
                backend = backend_cls(processing_pipeline=pipeline)
                return backend.convert(SigmaCollection.from_yaml(text), fmt)

            raw = run(target.format)
            rendered = _render(raw).strip()
            if not rendered:
                errors.append(("", f"{label}: the backend produced nothing"))
                continue
            query = None
            if target.query_format == target.format:
                query = rendered
            elif target.query_format:
                query = _render(run(target.query_format)).strip()
            return _row(
                target,
                "converted",
                pipeline=list(pipes),
                tried=tried,
                output=package.package(target.name, doc, f"{rendered}\n", raw),
                file=f"{package.slug(str(doc.get('title') or 'detection'))}.{target.ext}",
                query=query,
            )
        except Exception as exc:  # noqa: BLE001 -- each backend raises its own types
            errors.append((type(exc).__name__, f"{label}: {type(exc).__name__}: {exc}"))
    gap = bool(errors) and all(_mapping_gap(kind) for kind, _ in errors)
    return _row(
        target,
        "needs_field_mapping" if gap else "failed",
        tried=tried,
        error="\n".join(message for _, message in errors)[:800]
        or "No usable pipeline for this backend.",
    )


def convert(
    text: str, doc: Dict[str, Any], names: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """One row per wanted target, every target if none is named."""
    wanted = names or list(TARGETS)
    rows = []
    for name in wanted:
        target = TARGETS.get(name)
        if target is None:
            rows.append(
                {
                    "target": name,
                    "platform": name,
                    "status": "failed",
                    "measured_valid_pct": None,
                    "pipeline": [],
                    "tried": [],
                    "output": "",
                    "file": None,
                    "query": None,
                    "error": f"Unknown target. Known: {', '.join(TARGETS)}.",
                }
            )
        elif not pysigma_installed():
            rows.append(_row(target, "not_installed", error=PYSIGMA_MISSING))
        else:
            rows.append(_convert_one(text, doc, target))
    return rows


def pasted(language: str, query: str, by: str) -> Dict[str, Any]:
    """A person's own query for a target the overlay can hold. Vigil did not convert this."""
    target = TARGETS[_PASTABLE[language]]
    return _row(
        target,
        "pasted",
        output=f"{query.strip()}\n",
        query=query.strip(),
        error="",
        pasted_by=by,
    )


def pastable(language: str) -> bool:
    return language in _PASTABLE


_ESQL_START = re.compile(r"^\s*from\s", re.IGNORECASE)


def overlay_queries(rows: List[Dict[str, Any]]) -> Dict[str, Tuple[str, str]]:
    """What the overlay can hold: {'splunk': (query, 'spl'), 'elastic': (query, language)}."""
    usable = {
        row["target"]: row
        for row in rows
        if row["status"] in ("converted", "pasted") and row.get("query")
    }
    out: Dict[str, Tuple[str, str]] = {}
    if "splunk" in usable:
        out["splunk"] = (usable["splunk"]["query"], "spl")
    if "elastic-lucene" in usable:
        out["elastic"] = (usable["elastic-lucene"]["query"], "lucene")
    elif "elastic" in usable:
        query = usable["elastic"]["query"]
        out["elastic"] = (query, "esql" if _ESQL_START.match(query) else "lucene")
    return out
