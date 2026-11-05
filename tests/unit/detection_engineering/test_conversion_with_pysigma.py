"""Real pySigma conversion, for an install that added requirements-sigma.txt."""

import json
import tomllib

import pytest
import yaml

from core.detections.engineering import package, sigma_text, targets
from core.detections.overlay import _parse

from .conftest import RULE

pytest.importorskip("sigma.collection")
pytest.importorskip("sigma.backends.splunk")

TEXT, _ = sigma_text.fill_in(RULE, None)
DOC = sigma_text.parse(TEXT)


def _rows(*names):
    return {
        row["target"]: row for row in targets.convert(TEXT, DOC, list(names) or None)
    }


def test_splunk_lands_disabled_with_the_bare_query_kept_for_the_overlay():
    row = _rows("splunk")["splunk"]
    assert row["status"] == "converted" and row["pipeline"] == ["splunk_windows"]
    assert "disabled = 1" in row["output"]
    assert row["query"].startswith("ParentImage IN")
    assert "savedsearches" not in row["query"] and "[" not in row["query"].split()[0]


def test_each_format_is_what_its_siem_reads_and_lands_disabled():
    rows = _rows("sentinel", "elastic", "opensearch", "panther", "chronicle")
    sentinel = yaml.safe_load(rows["sentinel"]["output"])
    assert sentinel["kind"] == "Scheduled" and sentinel["status"] == "Disabled"
    assert sentinel["query"].startswith("imProcessCreate")
    assert json.loads(rows["elastic"]["output"])["enabled"] is False
    assert json.loads(rows["opensearch"]["output"])["enabled"] is False
    assert yaml.safe_load(rows["panther"]["output"])["Enabled"] is False
    assert rows["chronicle"]["output"].lstrip().startswith("rule office_application")


def test_a_field_a_backend_cannot_map_is_needs_field_mapping_not_a_silent_skip():
    text = TEXT.replace("CommandLine|contains", "ParentCommandLine|contains")
    row = targets.convert(text, sigma_text.parse(text), ["crowdstrike"])[0]
    assert row["status"] == "needs_field_mapping"
    assert "ParentCommandLine" in row["error"]
    assert row["output"] == ""


def test_a_log_source_a_pipeline_has_no_table_for_needs_field_mapping():
    text = TEXT.replace("category: process_creation", "category: ps_module")
    row = targets.convert(text, sigma_text.parse(text), ["sentinel"])[0]
    assert row["status"] == "needs_field_mapping"


def test_one_failing_target_does_not_hide_the_others():
    text = TEXT.replace("category: process_creation", "category: ps_module")
    rows = {r["target"]: r for r in targets.convert(text, sigma_text.parse(text))}
    assert len(rows) == 13
    assert rows["sentinel"]["status"] == "needs_field_mapping"
    assert rows["splunk"]["status"] == "converted"


def test_converted_queries_build_copies_the_overlay_reader_accepts():
    rows = list(_rows("splunk", "elastic-lucene").values())
    queries = targets.overlay_queries(rows)
    splunk = _parse("splunk", package.splunk_copy(DOC, queries["splunk"][0]))
    assert splunk.techniques == ["T1059.001"]
    elastic_text = package.elastic_copy(DOC, *queries["elastic"])
    elastic = _parse("elastic", elastic_text)
    assert elastic.techniques == ["T1059.001"]
    assert tomllib.loads(elastic_text)["rule"]["language"] == "lucene"
    assert splunk.native_key != elastic.native_key != DOC["id"]


def test_the_sigma_tree_replays_a_cidr_rule_vigils_evaluator_refuses():
    from core.detections.engineering.replay import matcher_for

    text = """
title: Connection into a subnet
logsource: {category: network_connection, product: windows}
detection:
  selection:
    DestinationIp|cidr: 198.51.100.0/24
  condition: selection
"""
    matcher, engine = matcher_for(text)
    assert engine == "sigma-tree"
    assert matcher({"DestinationIp": "198.51.100.7"}) is True
    assert matcher({"DestinationIp": "203.0.113.7"}) is False


@pytest.mark.database
def test_a_real_conversion_reaches_shadow_with_both_overlay_copies(
    add_case, add_event, attack_row, plain_row, person
):
    from core.detections.engineering import proposals

    case_id = add_case()
    add_event(attack_row, case_id=case_id)
    add_event(plain_row)
    pid = proposals.create(sigma=RULE, actor=person, case_id=case_id)["proposal_id"]
    proposals.lint(pid, person)
    proposals.replay(pid, person)
    view = proposals.convert(pid, person)
    rows = {r["target"]: r for r in view["latest"]["convert"]["evidence"]["targets"]}
    assert view["state"] == "converted"
    assert rows["splunk"]["status"] == "converted"
    assert rows["splunk"]["file"].endswith(".conf")
    view = proposals.shadow(pid, person)
    saved = view["latest"]["shadow"]["evidence"]["saved"]
    assert {row["source"] for row in saved} == {"splunk", "elastic", "sigma"}
    assert [s["stage"] for s in view["stages"]] == ["shadow", "shadow"]
