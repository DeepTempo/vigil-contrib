"""One search across alerts and cases: the words typed, and what they mean.

Candidates come from Postgres: every row whose title, description, entities,
raw record (alerts) or timeline (cases) holds any of the query's words, plus
the newest alerts and open cases so a query in other words still has something
to rank. Each candidate is scored by how many query words it holds and, when
the local Ollama has an embedding model, by how close its text is in meaning.
Each result says why it matched.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import OrderedDict
from typing import Callable, Optional, Sequence

from sqlalchemy import text

logger = logging.getLogger(__name__)

_WORD = re.compile(r"[a-z0-9][a-z0-9._:@\\/-]*", re.I)
_STOP = frozenset(
    "a an and are as at be by for from has have in is it of on or show me find any all the this that to was were what which "
    "with who where when about alerts alert cases case".split()
)
KEYWORD_WEIGHT = 0.45
MEANING_WEIGHT = 0.55
MIN_SCORE = 0.3

Embedder = Callable[[list[str]], Optional[list[list[float]]]]


class EmbeddingCache:
    """Vectors by text, so a row is embedded once per process, not per keystroke."""

    def __init__(self, size: int = 20000):
        self.size = size
        self._items: "OrderedDict[str, list[float]]" = OrderedDict()

    def embed(
        self, embed: Embedder, texts: Sequence[str]
    ) -> Optional[list[list[float]]]:
        keys = [hashlib.sha1(t.encode()).hexdigest() for t in texts]
        missing = [i for i, k in enumerate(keys) if k not in self._items]
        if missing:
            got = embed([texts[i] for i in missing])
            if got is None:
                return None
            for i, vec in zip(missing, got):
                self._items[keys[i]] = vec
            while len(self._items) > self.size:
                self._items.popitem(last=False)
        out = []
        for k in keys:
            self._items.move_to_end(k)
            out.append(self._items[k])
        return out


CACHE = EmbeddingCache()


def terms(query: str) -> list[str]:
    return [
        w.lower() for w in _WORD.findall(query) if w.lower() not in _STOP and len(w) > 1
    ]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _like_any(column_sql: str, words: list[str], params: dict, prefix: str) -> str:
    parts = []
    for i, w in enumerate(words):
        params[f"{prefix}{i}"] = f"%{w}%"
        parts.append(f"{column_sql} ilike :{prefix}{i}")
    return "(" + " or ".join(parts) + ")" if parts else "false"


def candidates(session, query: str, pool: int = 300) -> tuple[list[dict], list[dict]]:
    """Alert and case rows to rank: word matches first, then the newest."""
    words = terms(query) or [query.strip().lower()]
    params: dict = {"pool": pool}
    alert_text = (
        "coalesce(f.title,'') || ' ' || coalesce(f.description,'') || ' ' || f.finding_id || ' ' || "
        "coalesce(f.external_id,'') || ' ' || coalesce(f.data_source,'') || ' ' || "
        "coalesce((f.entity_context - 'source_evidence')::text,'') || ' ' || "
        "coalesce(f.entity_context->'source_evidence'->>'raw_text','')"
    )
    alert_cols = (
        "f.finding_id, f.title, f.description, f.severity, f.data_source, f.timestamp, f.noise_marked_at is not null as dropped, "
        f"{alert_text} as haystack"
    )
    alerts = (
        session.execute(
            text(f"""
            (select {alert_cols} from findings f where f.data_source <> 'probe' and {_like_any(alert_text, words, params, 'w')}
             order by f.timestamp desc nulls last limit :pool)
            union
            (select {alert_cols} from findings f where f.data_source <> 'probe' and f.noise_marked_at is null
             order by f.timestamp desc nulls last limit 150)
        """),
            params,
        )
        .mappings()
        .all()
    )
    case_text = (
        "c.case_id || ' ' || coalesce(c.title,'') || ' ' || coalesce(c.description,'') || ' ' || "
        "coalesce(array_to_string(c.tags, ' '),'') || ' ' || coalesce(c.activities::text,'') || ' ' || coalesce(c.notes::text,'')"
    )
    case_cols = f"c.case_id, c.title, c.description, c.status, c.priority, c.updated_at, {case_text} as haystack"
    cases = (
        session.execute(
            text(f"""
            (select {case_cols} from cases c where {_like_any(case_text, words, params, 'w')} order by c.updated_at desc limit :pool)
            union
            (select {case_cols} from cases c where c.status <> 'closed' order by c.updated_at desc limit 100)
        """),
            params,
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in alerts], [dict(r) for r in cases]


def rank(
    query: str,
    rows: list[dict],
    label: Callable[[dict], str],
    embed: Optional[Embedder],
    limit: int,
) -> tuple[list[dict], bool]:
    """Rows best first, each with ``score`` and ``reasons``; and whether meaning was used."""
    words = terms(query)
    if not rows:
        return [], False
    vectors = None
    if embed is not None:
        vectors = CACHE.embed(
            embed,
            [f"search_query: {query}"]
            + [f"search_document: {label(r)[:600]}" for r in rows],
        )
    out = []
    for i, row in enumerate(rows):
        hay = (row.get("haystack") or "").lower()
        hit = [w for w in words if w in hay]
        keyword = len(hit) / len(words) if words else 0.0
        meaning = max(0.0, _cosine(vectors[0], vectors[i + 1])) if vectors else 0.0
        # nomic's cosine for unrelated text sits near 0.4; stretch the useful band
        meaning_n = max(0.0, min(1.0, (meaning - 0.45) / 0.3)) if vectors else 0.0
        score = (
            KEYWORD_WEIGHT * keyword + MEANING_WEIGHT * meaning_n
            if vectors
            else keyword
        )
        if score < MIN_SCORE and not (keyword and not vectors):
            continue
        reasons = []
        if hit:
            reasons.append("mentions " + ", ".join(hit[:3]))
        if vectors and meaning_n >= 0.5:
            reasons.append("similar meaning")
        out.append(
            {
                **{k: v for k, v in row.items() if k != "haystack"},
                "score": round(score, 3),
                "reasons": reasons,
            }
        )
    out.sort(key=lambda r: r["score"], reverse=True)
    return out[:limit], bool(vectors)
