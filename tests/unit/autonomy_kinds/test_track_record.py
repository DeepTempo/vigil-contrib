"""The label rules, eligibility, demotion and the seam's stay rules. No database."""

from datetime import datetime, timedelta, timezone

import pytest

from core.autonomy.track_record import (
    ABOVE_SCOPE,
    POLICY_LIFETIME,
    POLICY_REASON_PREFIX,
    WINDOW,
    Adoption,
    AlertTally,
    CaseClosure,
    ImportedTally,
    Label,
    MarkedAlert,
    NoiseMark,
    Origin,
    Overturn,
    PolicyEventKind,
    TrackRecord,
    Verdict,
    build_records,
    daily_counts,
    demotion_due,
    is_vigil_close,
    stay_reason,
    why_not,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 4, 12, tzinfo=timezone.utc)
KIND = "sample-edr|Sample scanner touched a share"
RULE = "rule-1"


def _closure(case_id, *, category="false_positive", channel="cookie", at=None, ids=()):
    return CaseClosure(
        case_id=case_id,
        category=category,
        channel=channel,
        closed_by="person:closer",
        closed_at=at or NOW - timedelta(days=1),
        finding_ids=frozenset(ids),
        signatures=frozenset({KIND}),
    )


def _spaced(count):
    return [
        _closure(f"case-{i}", at=NOW - timedelta(hours=2 * (i + 1)))
        for i in range(count)
    ]


def _alert(finding_id="a", *, severity="low", mark=None):
    return (
        AlertTally(
            KIND, RULE, 1, int(severity in ABOVE_SCOPE), int(is_vigil_close(mark))
        ),
        MarkedAlert(finding_id, KIND, mark) if mark else None,
    )


def _records(alerts=(), closures=(), imported=(), overturns=(), **kw):
    tallies = [AlertTally(KIND, RULE, 0), *(tally for tally, _ in alerts)]
    marks = [mark for _, mark in alerts if mark]
    return build_records(tallies, marks, closures, imported, overturns, NOW, **kw)


def _rules(record):
    return {r["rule"] for r in why_not(record)}


def test_one_case_with_59_alerts_is_one_label():
    ids = [f"a{i}" for i in range(59)]
    record = _records([_alert(i) for i in ids], [_closure("case-1", ids=ids)])[KIND]
    assert record.alerts_seen == 59
    assert record.clean_labels == 1
    assert "enough_clean_labels" in _rules(record)


def test_59_cases_are_59_labels_and_58_are_not():
    assert "enough_clean_labels" in _rules(_records(closures=_spaced(58))[KIND])
    record = _records(closures=_spaced(59))[KIND]
    assert record.clean_labels == 59
    assert why_not(record) == []
    assert record.miss_bound == pytest.approx(0.0495, abs=0.001)


@pytest.mark.parametrize("kinds_on_case", [1, 2])
def test_a_case_labels_each_kind_it_holds_once(kinds_on_case):
    signatures = frozenset({KIND, "other|Other"} if kinds_on_case == 2 else {KIND})
    closure = CaseClosure(
        "case-1",
        "false_positive",
        "cookie",
        "person:closer",
        NOW - timedelta(days=1),
        frozenset(),
        signatures,
    )
    records = _records(closures=[closure])
    assert {s: r.clean_labels for s, r in records.items()} == dict.fromkeys(
        signatures, 1
    )


def _vigil_mark(i=0):
    return NoiseMark(
        NOW - timedelta(hours=2 * (i + 1)),
        "vigil",
        "agent",
        f"{POLICY_REASON_PREFIX}7",
    )


def test_what_vigil_closed_is_never_evidence_for_itself():
    alerts = [_alert(f"v{i}", mark=_vigil_mark(i)) for i in range(100)]
    record = _records(alerts)[KIND]
    assert record.closed_by_vigil == 100
    assert record.clean_labels == 0


@pytest.mark.parametrize(
    "closure",
    [
        _closure("agent", channel="agent"),
        _closure("no-channel", channel=None),
        _closure("unspecified", category="unspecified"),
        _closure("duplicate", category="duplicate"),
        _closure("unable", category="unable_to_resolve"),
        _closure("nonsense", category="not-a-category"),
    ],
)
def test_a_close_that_is_no_persons_determination_is_no_label(closure):
    record = _records(closures=[closure])
    assert not record or record[KIND].reviewed == 0


def test_an_agents_real_closure_does_not_count_either():
    record = _records(closures=[_closure("c", category="resolved", channel="agent")])
    assert not record or record[KIND].real_labels == 0


def test_a_noise_mark_counts_only_from_a_person():
    at = NOW - timedelta(days=1)
    alerts = [
        _alert("person", mark=NoiseMark(at, "person-1", "person", None)),
        _alert("agent", mark=NoiseMark(at, "run-1", "agent", "tool")),
        _alert("svc", mark=NoiseMark(at, "svc-1", "person", None)),
    ]
    record = _records(alerts, service_accounts=frozenset({"svc-1"}))[KIND]
    assert record.benign_here == 1


def test_a_noise_mark_on_a_closed_case_is_not_a_second_label():
    at = NOW - timedelta(days=2)
    alert = _alert("a", mark=NoiseMark(at, "person-1", "person", None))
    record = _records([alert], [_closure("c", ids=["a"])])[KIND]
    assert record.clean_labels == 1


def test_a_burst_of_closes_counts_for_nothing_but_a_real_one_in_it_still_counts():
    burst = [
        _closure(f"c{i}", at=NOW - timedelta(days=1, seconds=i)) for i in range(59)
    ]
    burst.append(
        _closure("real", category="resolved", at=NOW - timedelta(days=1, seconds=60))
    )
    record = _records(closures=burst)[KIND]
    assert record.clean_labels == 0
    assert record.bulk_ignored == 59
    assert record.real_labels == 1


def test_imported_tickets_are_labels_kept_apart_from_closures_here():
    record = _records(closures=[_closure("c")], imported=[ImportedTally(KIND, 58)])[
        KIND
    ]
    assert (record.benign_here, record.imported_benign) == (1, 58)
    assert record.clean_labels == 59
    assert why_not(record) == []


def test_an_imported_real_ticket_blocks():
    tickets = [ImportedTally(KIND, real=1, last_real_at=NOW - timedelta(days=1))]
    record = _records(closures=_spaced(59), imported=tickets)[KIND]
    assert record.imported_real == 1
    assert record.miss_bound is None
    assert _rules(record) == {"none_real"}


def test_only_the_window_counts():
    old = NOW - WINDOW - timedelta(days=1)
    record = _records(
        closures=[
            *_spaced(59),
            _closure("old-real", category="resolved", at=old),
        ]
    )[KIND]
    assert record.real_labels == 0
    assert why_not(record) == []
    assert not _records(closures=[_closure("old", at=old)]).get(KIND, None) or (
        _records(closures=[_closure("old", at=old)])[KIND].clean_labels == 0
    )


def test_eligibility_names_every_rule_it_fails():
    alerts = [_alert("high", severity="high"), _alert("crit", severity="critical")]
    record = _records(
        alerts,
        [_closure("real", category="resolved")],
        marked_not_benign=frozenset({KIND}),
    )[KIND]
    reasons = why_not(record)
    assert {r["rule"] for r in reasons} == {
        "enough_clean_labels",
        "none_real",
        "nothing_above_scope",
        "not_marked_not_benign",
    }
    assert "0 of 59 clean labels" in reasons[0]["why"]
    assert "2 high or critical" in " ".join(r["why"] for r in reasons)


def test_an_overturn_counts_as_real():
    record = _records(
        closures=_spaced(59),
        overturns=[Overturn(KIND, "f", NOW - timedelta(hours=1))],
    )[KIND]
    assert record.overturned == 1
    assert _rules(record) == {"none_real"}


ADOPTED = NOW - timedelta(days=10)
ADOPTION = Adoption(7, "person:a", "r", ADOPTED, 59)


def _real_label(at):
    return Label(KIND, Verdict.REAL, Origin.CASE, "c", at)


def test_a_real_closure_after_adoption_suspends():
    due = demotion_due(ADOPTION, [_real_label(ADOPTED + timedelta(days=1))], NOW)
    assert due.kind is PolicyEventKind.SUSPEND
    assert due.evidence["ref"] == "c"


def test_a_real_closure_before_adoption_does_not():
    assert (
        demotion_due(ADOPTION, [_real_label(ADOPTED - timedelta(days=1))], NOW) is None
    )


def test_a_policy_expires_at_its_lifetime_and_not_before():
    just_before = ADOPTED + POLICY_LIFETIME - timedelta(seconds=1)
    assert demotion_due(ADOPTION, [], just_before) is None
    due = demotion_due(ADOPTION, [], ADOPTED + POLICY_LIFETIME)
    assert due.kind is PolicyEventKind.EXPIRE


def test_the_window_outlives_a_policy_so_a_renewal_at_expiry_can_pass():
    assert WINDOW > POLICY_LIFETIME


TRIAGED = {
    "severity": "low",
    "recommended_action": "dismiss",
    "ai_triage": {"result": {"severity": "low"}},
}


@pytest.mark.parametrize(
    "over, source, stays",
    [
        ({}, "low", None),
        ({"severity": "medium"}, "medium", None),
        ({"recommended_action": "dismiss"}, "low", None),
        ({"recommended_action": None}, "low", "triage_did_not_dismiss"),
        ({"recommended_action": ""}, "low", "triage_did_not_dismiss"),
        ({"recommended_action": "monitor"}, "low", "triage_did_not_dismiss"),
        ({"ai_triage": None}, "low", "triage_failed"),
        ({"ai_triage_error": "boom"}, "low", "triage_failed"),
        ({"severity": "high"}, "low", "severity_out_of_scope"),
        ({"severity": "critical"}, "low", "severity_out_of_scope"),
        ({"severity": "info"}, "info", "severity_out_of_scope"),
        ({"severity": None}, None, "severity_out_of_scope"),
        ({}, "high", "severity_out_of_scope"),
        ({}, "critical", "severity_out_of_scope"),
        ({}, None, "severity_out_of_scope"),
        ({"recommended_action": "isolate"}, "low", "triage_did_not_dismiss"),
        ({"recommended_action": "block"}, "low", "triage_did_not_dismiss"),
        ({"recommended_action": "investigate"}, "low", "triage_did_not_dismiss"),
        (
            {"enrichment": {"threat_indicators": {"ip": 1}}},
            "low",
            "threat_intel_hit",
        ),
        (
            {"ai_triage": {"baseline": {"stage1": "escalate"}}},
            "low",
            "precedent_escalates",
        ),
    ],
)
def test_what_keeps_an_alert_in_the_queue(over, source, stays):
    assert stay_reason({**TRIAGED, **over}, source) == stays


def test_daily_counts_split_what_a_policy_closed_from_what_people_got():
    today = NOW.date()
    rows = [
        (today, False, 1),
        (today, True, 1),
        (today - timedelta(days=30), False, 1),
    ]
    days = daily_counts(rows, today, 3)
    assert [d["day"] for d in days] == [
        (today - timedelta(days=2)).isoformat(),
        (today - timedelta(days=1)).isoformat(),
        today.isoformat(),
    ]
    assert days[-1] == {"day": today.isoformat(), "asked": 1, "closed": 1}


def _tally(rule, seen=1):
    return AlertTally(KIND, rule, seen)


@pytest.mark.parametrize(
    "tallies, says",
    [
        ([_tally(None, 3)], "Known only by its title"),
        ([_tally("r1"), _tally("r2")], "2 different source rules"),
        (
            [_tally("r1"), _tally(None, 4)],
            "4 alerts with this title name no source rule",
        ),
    ],
)
def test_a_kind_is_only_eligible_as_one_source_rule(tallies, says):
    records = build_records(tallies, (), _spaced(59), (), (), NOW)
    assert records[KIND].rule_id is None
    reasons = why_not(records[KIND])
    assert [r["rule"] for r in reasons] == ["one_source_rule"]
    assert says in reasons[0]["why"]


def test_one_source_rule_with_the_evidence_is_eligible():
    records = build_records([_tally("r1", 9)], (), _spaced(59), (), (), NOW)
    assert records[KIND].rule_id == "r1"
    assert why_not(records[KIND]) == []


def test_a_connectors_fallback_title_names_no_detection():
    signature = "crowdstrike|CrowdStrike Detection"
    record = TrackRecord(signature, benign_here=59, rule_ids={"pattern:1"})
    assert [r["rule"] for r in why_not(record)] == ["names_a_detection"]


def test_a_record_read_short_of_the_whole_install_cannot_be_adopted():
    record = TrackRecord(KIND, benign_here=59, rule_ids={"r1"}, incomplete=True)
    assert [r["rule"] for r in why_not(record)] == ["whole_record_read"]
