"""The rule text and lint steps, no database: what a reviewer reads off the checks."""

import pytest

from core.detections.engineering import lint, sigma_text
from core.detections.engineering import targets
from core.detections.engineering.targets import convert, sigma_error
from core.detections.tools import _replay_sigma

from .conftest import RULE


def _checks(report):
    return {check["name"]: check for check in report["checks"]}


def test_fill_in_adds_what_a_reviewer_would_and_keeps_an_id_across_edits():
    text, fixes = sigma_text.fill_in(RULE, "T1059.001")
    doc = sigma_text.parse(text)
    assert "added id" in fixes
    assert doc["tags"] == ["attack.execution", "attack.t1059.001"]
    assert sigma_text.fill_in(text, "T1059.001") == (text, [])


def test_fill_in_leaves_text_that_is_no_rule_for_lint_to_refuse():
    assert sigma_text.fill_in("not: [valid", None) == ("not: [valid", [])
    assert sigma_text.fill_in("a: 1\n---\nb: 2\n", None) == ("a: 1\n---\nb: 2\n", [])


def test_a_good_rule_passes_and_says_a_check_it_could_not_run():
    report = lint.lint_rule(RULE, None)
    assert report["passed"] is True
    fields = _checks(report)["Reads fields this install logs"]
    assert fields["passed"] is None and "no rows" in fields["detail"]


def test_a_rule_keyed_to_one_address_is_refused_by_vigils_lint():
    text = RULE.replace("CommandLine|contains: '-enc'", "DestinationIp: 203.0.113.9")
    report = lint.lint_rule(text, None)
    assert report["passed"] is False
    assert (
        _checks(report)["Not tied to one host, address or account"]["passed"] is False
    )
    assert report["findings"][0]["value"] == "203.0.113.9"


def test_a_field_no_stored_event_has_is_named_but_does_not_block():
    report = lint.lint_rule(RULE, {"Image", "CommandLine"})
    fields = _checks(report)["Reads fields this install logs"]
    assert report["passed"] is True
    assert fields["passed"] is False and "ParentImage" in fields["detail"]


def test_structure_is_blocking_and_advice_is_not():
    assert lint.lint_rule("title: only a title\n", None)["passed"] is False
    bare = "title: x\nlogsource: {product: windows}\ndetection: {a: {b: c}, condition: a}\n"
    report = lint.lint_rule(bare, None)
    assert report["passed"] is True
    assert _checks(report)["Tagged with an ATT&CK technique"]["passed"] is False


def test_an_exclusion_narrows_every_condition_and_replays_as_a_person_expects(
    attack_row, signed_macro_row
):
    exclusion = sigma_text.Exclusion(
        "ParentCommandLine", "contains", ("trusted-macros",)
    )
    tuned = sigma_text.add_exclusion(RULE, exclusion)
    assert _replay_sigma(RULE, [attack_row], [signed_macro_row])["ruled_out_matched"]
    replay = _replay_sigma(tuned, [attack_row], [signed_macro_row])
    assert replay["matched"] is True and replay["ruled_out_matched"] is False

    again = sigma_text.add_exclusion(
        tuned, sigma_text.Exclusion("Image", "endswith", ("\\calc.exe",))
    )
    detection = sigma_text.parse(again)["detection"]
    assert {"filter_person_1", "filter_person_2"} <= set(detection)
    assert detection["condition"].count("not filter_person") == 2


@pytest.mark.parametrize(
    "field,match,values",
    [("a|re", "contains", ("x",)), ("a", "regex", ("x",)), ("a", "contains", ())],
)
def test_a_bad_exclusion_is_refused(field, match, values):
    with pytest.raises(sigma_text.NotARule):
        sigma_text.Exclusion(field, match, values)


def test_an_exclusion_needs_a_rule_it_can_change():
    with pytest.raises(sigma_text.NotARule):
        sigma_text.add_exclusion(
            "title: x\n", sigma_text.Exclusion("a", "contains", ("b",))
        )


def test_without_pysigma_every_target_fails_honestly_and_no_output_is_invented(
    monkeypatch,
):
    monkeypatch.setattr(targets, "pysigma_installed", lambda: False)
    rows = convert(RULE, sigma_text.parse(RULE))
    assert len(rows) == 13
    assert {row["status"] for row in rows} == {"not_installed"}
    assert all("requirements.lock" in row["error"] for row in rows)
    assert not any(row["output"] for row in rows)
    assert sigma_error(RULE) is not None


def test_an_unknown_target_is_one_failed_row_not_an_error():
    rows = convert(RULE, sigma_text.parse(RULE), ["no-such-siem"])
    assert rows[0]["status"] == "failed" and "Unknown target" in rows[0]["error"]
