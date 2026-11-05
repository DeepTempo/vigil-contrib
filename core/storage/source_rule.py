"""Which rule in the source raised a finding, kept apart from the title an alert can write.

Only an adapter reading the source's own rule field builds a ``SourceRule``, and only a
``SourceRule`` reaches the ``findings.source_rule`` column. The rule is read from that column
alone. A string under this key in ``entity_context``, whether it came from a request, an upload
or a row an older version stored, is never read as a rule.
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

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


def split_source_rule(entity_context: Any) -> Tuple[Optional[SourceRule], Any]:
    """The adapter's rule on ``entity_context``, and the context without the key."""
    if not isinstance(entity_context, dict) or ENTITY_CONTEXT_KEY not in entity_context:
        return None, entity_context
    rest = {k: v for k, v in entity_context.items() if k != ENTITY_CONTEXT_KEY}
    rule = entity_context[ENTITY_CONTEXT_KEY]
    return (rule if isinstance(rule, SourceRule) else None), rest
