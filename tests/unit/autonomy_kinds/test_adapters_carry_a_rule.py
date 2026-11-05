"""Each connector carries the source's own rule field, never a title it fell back to."""

import pytest

from core.integrations.aws_security_hub.ingestion import AWSSecurityHubIngestion
from core.integrations.azure_sentinel.ingestion import AzureSentinelIngestion
from core.integrations.crowdstrike.adapter import _detection_to_finding
from core.integrations.elastic.ingestion import ElasticIngestion
from core.integrations.microsoft_defender.ingestion import MicrosoftDefenderIngestion
from core.integrations.opensearch.ingestion import OpenSearchIngestion
from core.integrations.splunk.adapter import _splunk_event_to_finding
from core.storage.source_rule import SourceRule
from services.daemon.poller import DataPoller

pytestmark = pytest.mark.unit


def _transform(cls, alert):
    return cls.__new__(cls).transform_alert_to_finding(alert)


def _elastic(source):
    return _transform(ElasticIngestion, {"_id": "e1", "_source": source})


def _hub(alert):
    return _transform(AWSSecurityHubIngestion, {"Id": "h1", **alert})


def _sentinel(alert):
    return _transform(AzureSentinelIngestion, {"id": "s1", **alert})


def _defender(alert):
    return _transform(
        MicrosoftDefenderIngestion, {"alertId": "d1", "id": "d1", **alert}
    )


def _opensearch(queries):
    return _transform(
        OpenSearchIngestion, {"_id": "o1", "_source": {"id": "o1", "queries": queries}}
    )


def _crowdstrike(**detection):
    return _detection_to_finding({"detection_id": "c1", **detection})


@pytest.mark.parametrize(
    "finding, rule",
    [
        (
            _elastic(
                {
                    "kibana.alert.rule.rule_id": "rule-1",
                    "kibana.alert.rule.uuid": "uuid-1",
                    "kibana.alert.rule.name": "N",
                }
            ),
            "rule-1",
        ),
        (
            _elastic({"signal": {"rule": {"rule_id": "rule-1", "id": "uuid-1"}}}),
            "rule-1",
        ),
        (_elastic({"signal": {"rule": {"id": "sig-1", "name": "N"}}}), "sig-1"),
        (
            _elastic(
                {"kibana.alert.rule.uuid": "uuid-1", "kibana.alert.rule.name": "N"}
            ),
            "uuid-1",
        ),
        (_elastic({"rule": {"level": 3, "id": "5710", "description": "Sshd"}}), "5710"),
        (
            _splunk_event_to_finding({"_cd": "1", "search_name": "Failed logins"}),
            "Failed logins",
        ),
        (_splunk_event_to_finding({"_cd": "1", "rule_name": "ES rule"}), "ES rule"),
        (
            _crowdstrike(behaviors=[{"pattern_id": 10}, {"pattern_id": 10}]),
            "pattern:10",
        ),
        (_crowdstrike(pattern_id=10, scenario="x"), "pattern:10"),
        (_crowdstrike(behaviors=[{"pattern_id": 10}], scenario="x"), "pattern:10"),
        (_crowdstrike(pattern_id=10), "pattern:10"),
        (_sentinel({"title": "T", "analytic_rule_ids": ["rule-a"]}), "rule-a"),
        (_defender({"title": "T", "detectorId": "det-1"}), "det-1"),
        (_hub({"Title": "T", "GeneratorId": "aws/iam.1"}), "aws/iam.1"),
        (_opensearch([{"id": "sig-a", "name": "T"}]), "sig-a"),
    ],
)
def test_a_real_rule_field_is_carried_as_trusted(finding, rule):
    carried = finding["entity_context"]["source_rule"]
    assert carried == rule
    assert isinstance(carried, SourceRule)


@pytest.mark.parametrize(
    "finding",
    [
        _elastic({"host": {"name": "h"}}),
        _splunk_event_to_finding({"_cd": "1"}),
        _crowdstrike(),
        _crowdstrike(behaviors=[{"pattern_id": 10}, {"pattern_id": 11}]),
        _crowdstrike(scenario="credential_theft"),
        _crowdstrike(behaviors=[{"pattern_id": 10}, {"pattern_id": 11}], scenario="x"),
        _crowdstrike(behaviors=[{}], scenario="x"),
        _sentinel({"title": "T"}),
        _sentinel({"title": "T", "analytic_rule_ids": ["a", "b"]}),
        _defender({"title": "T"}),
        _hub({"Title": "T"}),
        _opensearch([]),
        _opensearch([{"id": "a"}, {"id": "b"}]),
    ],
)
def test_a_source_that_names_no_single_rule_carries_none(finding):
    assert "source_rule" not in (finding["entity_context"] or {})


@pytest.mark.parametrize(
    "detection, rule",
    [
        ({"scenario": "x"}, None),
        ({"scenario": "x", "behaviors": [{"pattern_id": 10}]}, "pattern:10"),
        (
            {"scenario": "x", "behaviors": [{"pattern_id": 10}, {"pattern_id": 11}]},
            None,
        ),
        ({}, None),
    ],
)
def test_the_poller_and_the_adapter_name_the_same_crowdstrike_rule(detection, rule):
    detection = {"detection_id": "c1", **detection}
    polled = DataPoller.__new__(DataPoller)._crowdstrike_detection_to_finding(detection)
    fetched = _detection_to_finding(detection)
    assert polled["entity_context"].get("source_rule") == rule
    assert fetched["entity_context"].get("source_rule") == rule
