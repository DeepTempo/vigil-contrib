"""The story as a pure function: what the rows support, and nothing else."""

from datetime import datetime, timedelta

from core.incidents.story import (
    ActionEffect,
    CaseFacts,
    ClosureFacts,
    Coverage,
    EvidenceKind,
    FindingFacts,
    HuntVerdictFacts,
    InstallFacts,
    IocFacts,
    LogFacts,
    ReasonKind,
    Report,
    RuleInventory,
    StoryFacts,
    VerdictValue,
    build_story,
    entity_overlap,
)
from core.response.approval_service import PendingAction

T0 = datetime(2026, 3, 2, 10, 0, 0)
CASE = CaseFacts(
    case_id="case-1", title="Beacon and share access", status="open", created_at=T0
)


def finding(fid: str, minute: int = 0, **fields) -> FindingFacts:
    fields.setdefault("title", f"Alert {fid}")
    return FindingFacts(
        finding_id=fid, created_at=T0 + timedelta(minutes=minute), **fields
    )


def approval(action_id: str = "act-1", **fields) -> PendingAction:
    defaults = dict(
        action_id=action_id,
        action_type="block_ip",
        title=f"Block for {action_id}",
        description="Stop the traffic",
        target="198.51.100.7",
        confidence=0.8,
        reason="Beaconing seen",
        evidence=[],
        created_at="2026-03-02T10:30:00+00:00",
        created_by="agent",
        requires_approval=True,
        status="pending",
    )
    return PendingAction(**{**defaults, **fields})


def story(*findings, **facts):
    overlap = facts.pop("overlap", entity_overlap(findings))
    case = facts.pop("case", CASE)
    return build_story(
        StoryFacts(case=case, findings=findings, overlap=overlap, **facts)
    )


def kinds(built) -> set:
    return {reason.kind for reason in built.reasons}


def test_steps_run_in_time_order_with_their_technique_and_source():
    built = story(
        finding(
            "late",
            30,
            data_source="edr",
            labels=[("T1071.001", 0.4), ("T1059.001", 0.9)],
        ),
        finding("early", 1, data_source="mail", timestamp=T0 - timedelta(hours=2)),
    )
    assert [s.finding_id for s in built.steps] == ["early", "late"]
    assert built.steps[0].source == "mail"
    late = built.steps[1]
    assert late.technique.id == "T1059.001"
    assert late.technique.tactic == "Execution"
    assert [t.id for t in late.other_techniques] == ["T1071.001"]


def test_a_tactic_label_is_kept_and_is_not_called_a_technique():
    step = story(finding("a", labels=[("execution", 0.7)]), finding("b")).steps[0]
    assert step.technique is None
    assert step.labels == ["execution"]


def test_alerts_that_share_nothing_earn_no_reason():
    built = story(finding("a", data_source="edr"), finding("b", data_source="edr"))
    assert built.reasons == []


def test_every_reason_carries_links_to_rows_that_exist():
    built = story(
        finding(
            "a",
            data_source="edr",
            severity="critical",
            anomaly_score=0.91,
            labels=[("T1059.001", 0.9)],
            entity_context={"hostnames": ["wks-9"], "src_ips": ["198.51.100.7"]},
        ),
        finding(
            "b",
            5,
            data_source="netflow",
            labels=[("T1071.001", None)],
            entity_context={"hostnames": ["WKS-9"], "dest_ips": ["198.51.100.7"]},
        ),
        logs=LogFacts(events=12, unusual=3),
        approvals=[approval(status="approved", approved_by="dana")],
        iocs=[
            IocFacts(
                kind="ip",
                value="198.51.100.7",
                threat_level="high",
                source="intel-feed",
            )
        ],
    )
    assert kinds(built) == {
        ReasonKind.SHARED_ENTITY,
        ReasonKind.SEVERAL_SOURCES,
        ReasonKind.TECHNIQUE_CHAIN,
        ReasonKind.UNUSUAL_SCORE,
        ReasonKind.HIGH_SEVERITY,
        ReasonKind.FLAGGED_INTEL,
        ReasonKind.LOG_EVENTS,
        ReasonKind.PERSON_APPROVED,
    }
    for reason in built.reasons:
        assert reason.evidence
        for link in reason.evidence:
            if link.kind is EvidenceKind.FINDING:
                assert link.ref in {"a", "b"}
            elif link.kind is EvidenceKind.LOG_SEARCH:
                assert link.ref == "case-1"
            else:
                assert link.ref == "act-1"


def test_a_shared_entity_reason_counts_what_it_says():
    built = story(
        finding("a", entity_context={"usernames": ["dana"]}),
        finding("b", entity_context={"usernames": ["Dana"]}),
        finding("c"),
    )
    assert [r.text for r in built.reasons] == [
        "2 of 3 alerts name the same user, dana."
    ]


def test_a_placeholder_entity_links_nothing():
    built = story(
        finding("a", entity_context={"hostnames": ["unknown"]}),
        finding("b", entity_context={"hostnames": ["unknown"]}),
    )
    assert built.entities == []
    assert built.reasons == []


def test_the_daemons_merge_note_is_a_reason_only_for_alerts_still_on_the_case():
    case = CaseFacts(
        case_id="case-1",
        title="t",
        status="open",
        created_at=T0,
        activities=[
            {
                "activity_type": "alert_added",
                "details": {"finding_id": "b", "matched_key": "ip:198.51.100.7"},
            },
            {
                "activity_type": "alert_added",
                "details": {"finding_id": "gone", "matched_key": "hostname:wks-2"},
            },
            {
                "activity_type": "note",
                "details": {"finding_id": "a", "matched_key": "ip:203.0.113.4"},
            },
        ],
    )
    built = story(finding("a"), finding("b"), case=case)
    merge = [r for r in built.reasons if r.kind is ReasonKind.DAEMON_MERGE]
    assert len(merge) == 1
    assert "same ip, 198.51.100.7" in merge[0].text
    assert [e.ref for e in merge[0].evidence] == ["b"]


def test_a_low_score_and_unflagged_intel_are_not_reasons():
    built = story(
        finding("a", anomaly_score=0.2, entity_context={"src_ips": ["198.51.100.7"]}),
        finding("b"),
        iocs=[IocFacts(kind="ip", value="198.51.100.7", threat_level="low")],
    )
    assert ReasonKind.UNUSUAL_SCORE not in kinds(built)
    assert ReasonKind.FLAGGED_INTEL not in kinds(built)
    assert built.intel[0].threat_level == "low"


def test_flagged_intel_no_alert_names_is_shown_but_is_not_a_reason():
    built = story(
        finding("a"),
        finding("b"),
        iocs=[
            IocFacts(kind="domain", value="bad.example.net", threat_level="critical")
        ],
    )
    assert built.reasons == []
    assert [i.value for i in built.intel] == ["bad.example.net"]


def test_no_log_events_means_no_log_evidence():
    built = story(finding("a"), finding("b"))
    assert built.log_events == 0
    assert ReasonKind.LOG_EVENTS not in kinds(built)


def test_a_pending_or_rejected_approval_is_not_a_reason():
    built = story(
        finding("a"),
        finding("b"),
        approvals=[approval("p"), approval("r", status="rejected", approved_by="dana")],
    )
    assert ReasonKind.PERSON_APPROVED not in kinds(built)


def test_coverage_says_what_stands_behind_each_step():
    rules = RuleInventory(by_technique={"T1059.001": ["Encoded shell"]}, loaded=1)
    built = story(
        finding(
            "fired",
            entity_context={"rule_name": "Vendor rule 7"},
            labels=[("T1003", 0.5)],
        ),
        finding("declared", 1, labels=[("t1059.001", 0.9)]),
        finding("gap", 2, labels=[("T1003", 0.5)]),
        finding("scored", 3, anomaly_score=0.8),
        finding("silent", 4),
        rules=rules,
    )
    by_id = {s.finding_id: s for s in built.steps}
    assert by_id["fired"].coverage is Coverage.RULE_FIRED
    assert by_id["fired"].caught_by == "Vendor rule 7"
    assert by_id["declared"].coverage is Coverage.RULE_DECLARED
    assert by_id["declared"].caught_by == "Encoded shell"
    assert by_id["gap"].coverage is Coverage.NO_RULE
    assert by_id["scored"].coverage is Coverage.NO_RULE
    assert by_id["silent"].coverage is Coverage.UNKNOWN
    assert [s.finding_id for s in built.unmatched_steps] == ["gap", "scored"]


def test_an_empty_inventory_says_so():
    built = story(finding("a", labels=[("T1003", 0.5)]), finding("b"))
    assert built.rules_loaded == 0
    assert built.unmatched_steps[0].coverage_note == (
        "No rules are loaded in the inventory, so none declares T1003."
    )


def test_no_verdict_is_said_plainly():
    verdict = story(finding("a"), finding("b")).verdict
    assert verdict.value is VerdictValue.UNDETERMINED
    assert verdict.by is None


def test_a_persons_close_is_their_verdict():
    closed = CaseFacts(case_id="case-1", title="t", status="closed", created_at=T0)
    verdict = story(
        finding("a"),
        finding("b"),
        case=closed,
        closure=ClosureFacts(
            category="resolved",
            channel="cookie",
            closed_by="dana",
            notes="Confirmed on the host.",
        ),
    ).verdict
    assert verdict.value is VerdictValue.TRUE_POSITIVE
    assert verdict.by == "person"
    assert "Confirmed on the host." in verdict.basis
    assert verdict.model_words is None


def test_an_agents_close_keeps_its_notes_as_the_models_words():
    closed = CaseFacts(case_id="case-1", title="t", status="closed", created_at=T0)
    verdict = story(
        finding("a"),
        finding("b"),
        case=closed,
        closure=ClosureFacts(
            category="false_positive", channel="agent", notes="Scheduled scan."
        ),
    ).verdict
    assert verdict.value is VerdictValue.FALSE_POSITIVE
    assert verdict.by == "agent"
    assert verdict.model_words == "Scheduled scan."


def test_a_close_with_no_determination_is_not_a_verdict():
    closed = CaseFacts(case_id="case-1", title="t", status="closed", created_at=T0)
    verdict = story(
        finding("a"),
        finding("b"),
        case=closed,
        closure=ClosureFacts(category="unspecified", channel="cookie"),
    ).verdict
    assert verdict.value is VerdictValue.UNDETERMINED


def test_a_reopened_case_ignores_its_old_closure():
    verdict = story(
        finding("a"),
        finding("b"),
        closure=ClosureFacts(category="resolved", channel="cookie"),
    ).verdict
    assert verdict.value is VerdictValue.UNDETERMINED


def test_a_runs_proven_verdict_is_labelled_as_the_models():
    hunt = HuntVerdictFacts(
        outcome="proven",
        statement="Lateral movement happened.",
        rationale="Two hosts share the tool.",
        concluded_at=T0,
        investigation_id="run-4",
    )
    verdict = story(finding("a"), finding("b"), hunt_verdicts=[hunt]).verdict
    assert verdict.value is VerdictValue.TRUE_POSITIVE
    assert verdict.by == "agent"
    assert verdict.model_words == "Lateral movement happened. Two hosts share the tool."


def test_a_disproven_hypothesis_does_not_clear_the_case():
    hunt = HuntVerdictFacts(
        outcome="disproven",
        statement="s",
        rationale="r",
        concluded_at=T0,
        investigation_id="run-4",
    )
    assert (
        story(finding("a"), finding("b"), hunt_verdicts=[hunt]).verdict.value
        is VerdictValue.UNDETERMINED
    )


def test_a_report_is_passed_through_untouched():
    report = Report(text="The model wrote this.", origin="workflow_run", ref="run-4")
    assert (
        story(finding("a"), finding("b"), report=report).report.text
        == "The model wrote this."
    )


def action_for(install=InstallFacts(), **fields):
    return story(
        finding("a"), finding("b"), approvals=[approval(**fields)], install=install
    ).actions[0]


def test_a_recommendation_says_nothing_runs():
    action = action_for()
    assert action.effect is ActionEffect.RECORD_ONLY
    assert "nothing changes on your network" in action.does
    assert action.missing


def test_cloudflare_with_the_integration_off_says_nothing_changes():
    action = action_for(action_type="waf_block")
    assert action.effect is ActionEffect.CLOUDFLARE
    assert "marks it failed" in action.does
    assert "integration is off" in action.missing


def test_cloudflare_with_no_token_says_so():
    action = action_for(
        InstallFacts(cloudflare_enabled=True), action_type="gateway_block"
    )
    assert "no API token" in action.missing


def test_cloudflare_configured_says_what_the_executor_does():
    action = action_for(
        InstallFacts(cloudflare_enabled=True, cloudflare_token=True),
        action_type="waf_block",
    )
    assert action.missing is None
    assert "adds a Cloudflare WAF block on 198.51.100.7" in action.does


def test_stop_is_named_when_it_holds_execution():
    action = action_for(
        InstallFacts(
            cloudflare_enabled=True, cloudflare_token=True, execution_held=True
        ),
        action_type="waf_block",
    )
    assert "Stop is on" in action.does


def test_isolation_has_no_executor_and_says_so():
    action = action_for(action_type="isolate_host")
    assert action.effect is ActionEffect.NO_EXECUTOR
    assert "not touched" in action.does
    assert "no EDR executor" in action.missing


def test_a_run_linked_approval_resumes_the_run():
    action = action_for(action_type="workflow_phase", workflow_run_id="run-9")
    assert action.effect is ActionEffect.RUN_RESUMES
    assert "run-9" in action.does
    assert action.missing is None


def test_the_executors_real_result_is_shown():
    failed = action_for(
        action_type="waf_block",
        status="failed",
        execution_result={"error": "cloudflare_integration_disabled"},
    )
    assert failed.result == "cloudflare_integration_disabled"
    assert action_for(status="approved").result is None


def test_pending_actions_come_first_and_cite_only_this_cases_alerts():
    built = story(
        finding("a"),
        finding("b"),
        approvals=[
            approval(
                "done",
                status="approved",
                approved_by="dana",
                created_at="2026-03-01T00:00:00+00:00",
            ),
            approval("open", evidence=["a", "not-on-this-case"]),
        ],
    )
    assert [a.action_id for a in built.actions] == ["open", "done"]
    assert [e.ref for e in built.actions[0].evidence] == ["a"]


def test_the_rule_on_a_stored_reason_is_not_shown_as_the_reason():
    action = action_for(
        reason="Beaconing seen; response.confidence_threshold=0.90 not met (0.80)"
    )
    assert action.reason == "Beaconing seen"


def test_entities_are_most_named_first_with_who_names_them():
    entities = entity_overlap(
        [
            finding(
                "a", entity_context={"hostnames": ["solo"], "src_ip": "198.51.100.7"}
            ),
            finding("b", entity_context={"dest_ips": ["198.51.100.7"]}),
        ]
    )
    assert [(e.kind, e.value, e.finding_ids) for e in entities] == [
        ("ip", "198.51.100.7", ["a", "b"]),
        ("host", "solo", ["a"]),
    ]
