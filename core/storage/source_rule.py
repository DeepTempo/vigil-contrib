"""Which rule in the source raised a finding, kept apart from the title an alert can write.

Only an adapter reading the source's own rule field builds a ``SourceRule``. Anything parsed from
a request, webhook, upload or stored row is a plain string, and the Finding model drops a plain
string on its way in, so no route can claim a rule by sending this key.
"""

from __future__ import annotations

from typing import Any, Optional

ENTITY_CONTEXT_KEY = "source_rule"
MAX_RULE_CHARS = 255

# What a connector writes as the title when the source named nothing.
FALLBACK_TITLES = frozenset(
    {
        "AWS Security Hub Finding",
        "Azure Sentinel Incident",
        "CrowdStrike Detection",
        "Elastic Security Alert",
        "Microsoft Defender Alert",
        "OpenSearch Security Analytics Finding",
        "Splunk Alert",
        "Untitled alert",
        "Wazuh Alert",
    }
)


class SourceRule(str):
    """A rule identifier an adapter read from the source's own rule field."""


def with_source_rule(entity_context: Any, identifier: Any) -> Any:
    """``entity_context`` carrying this rule, or as it was when the source named none."""
    value = str(identifier).strip() if identifier not in (None, "") else ""
    if not value or len(value) > MAX_RULE_CHARS:
        return entity_context
    return {**(entity_context or {}), ENTITY_CONTEXT_KEY: SourceRule(value)}


def trusted_rule_only(entity_context: Any) -> Any:
    if not isinstance(entity_context, dict) or isinstance(
        entity_context.get(ENTITY_CONTEXT_KEY, SourceRule()), SourceRule
    ):
        return entity_context
    return {k: v for k, v in entity_context.items() if k != ENTITY_CONTEXT_KEY}


def source_rule_of(entity_context: Any) -> Optional[str]:
    """The rule on a stored finding. The model only lets a real one in."""
    if not isinstance(entity_context, dict):
        return None
    value = entity_context.get(ENTITY_CONTEXT_KEY)
    return value if isinstance(value, str) and value else None


def source_rule_column(column: Any) -> Any:
    """The same read in SQL, for a JSONB ``entity_context`` column."""
    return column[ENTITY_CONTEXT_KEY].astext
