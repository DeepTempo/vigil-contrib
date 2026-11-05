"""Detection engineering: proposals and their steps, and the program view around them.

Every step is a person's or a tool's event on the proposal. A proposal is rejected, never deleted.
Nothing here writes to a SIEM, and Vigil does not run Atomic Red Team: a run's events are uploaded.
"""

from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.auth.current_user import get_current_user
from core.auth.permissions import deny_unless, missing_permission, permission_gate
from core.detections.engineering import program, proposals, sigma_text, targets
from core.detections.engineering.replay import DEFAULT_WINDOW_DAYS
from core.detections.overlay import Refused
from core.llm.oneshot import NoProviderConfigured
from core.routing import Auth, RouterMeta
from core.storage.models import User
from core.storage.models.detection_proposal import InvalidProposalMove, ProposalState

router = APIRouter()
router.dependencies.append(permission_gate("detections.read"))

ROUTER_META = RouterMeta(
    prefix="/api/detection-engineering",
    tags=["detection-engineering"],
    auth=Auth.REQUIRED,
)

_WRITE = [permission_gate("detections.write")]
_READ_FINDINGS = "findings.read"
_READ_CASES = "cases.read"


def _require(user: User, *permissions: str) -> None:
    for permission in permissions:
        deny_unless(user.user_id, permission)


def _may_read_replay(user: User, proposal_id: str) -> None:
    """A replay reports log rows, and on a case's rule it reads that case's rows."""
    _require(user, _READ_FINDINGS)
    if proposals.case_of(proposal_id):
        _require(user, _READ_CASES)


def _reads(user: User, permission: str) -> bool:
    return missing_permission(user.user_id, permission) is None


def _all_shown(user: User, views: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reads_findings = _reads(user, _READ_FINDINGS)
    reads_cases = _reads(user, _READ_CASES)
    return [
        proposals.shown_to(view, reads_findings=reads_findings, reads_cases=reads_cases)
        for view in views
    ]


def _shown(user: User, view: Dict[str, Any]) -> Dict[str, Any]:
    return _all_shown(user, [view])[0]


@contextmanager
def _answers() -> Iterator[None]:
    """A refused step is the answer: it says what is needed, and nothing moved."""
    try:
        yield
    except proposals.NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InvalidProposalMove as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Refused as exc:
        raise HTTPException(
            status_code=422, detail={"message": str(exc), **exc.detail}
        ) from exc


class PasteRequest(BaseModel):
    sigma: str = Field(min_length=1, max_length=100_000)
    title: Optional[str] = Field(default=None, max_length=300)
    technique: Optional[str] = Field(default=None, max_length=16)
    case_id: Optional[str] = Field(default=None, max_length=50)
    finding_id: Optional[str] = Field(default=None, max_length=50)


class DraftRequest(BaseModel):
    case_id: Optional[str] = Field(default=None, max_length=50)
    finding_id: Optional[str] = Field(default=None, max_length=50)
    technique: Optional[str] = Field(default=None, max_length=16)
    notes: str = Field(default="", max_length=4000)


class FromRuleRequest(BaseModel):
    rule_id: int


class EditRequest(BaseModel):
    sigma: str = Field(min_length=1, max_length=100_000)
    reason: str = Field(default="", max_length=2000)


class ReplayRequest(BaseModel):
    event_ids: Optional[List[str]] = Field(default=None, max_length=2000)
    window_days: int = Field(default=DEFAULT_WINDOW_DAYS, ge=1, le=365)


class TuneRequest(BaseModel):
    field: str = Field(min_length=1, max_length=128)
    match: Literal["contains", "startswith", "endswith", "equals"] = "contains"
    values: List[str] = Field(min_length=1, max_length=50)
    reason: str = Field(max_length=2000)


class ConvertRequest(BaseModel):
    targets: Optional[List[str]] = Field(default=None, max_length=32)
    pasted: Optional[Dict[str, str]] = None
    accept_reason: str = Field(default="", max_length=2000)


class ReasonRequest(BaseModel):
    reason: str = Field(default="", max_length=2000)


class ThreatModelRequest(BaseModel):
    sector: str = Field(default="", max_length=4000)
    crown_jewels: str = Field(default="", max_length=4000)
    exposure: str = Field(default="", max_length=4000)
    advisories: str = Field(default="", max_length=4000)
    notes: str = Field(default="", max_length=4000)
    priority_techniques: List[str] = Field(default_factory=list, max_length=500)


class RedTeamRequest(BaseModel):
    name: str = Field(default="", max_length=200)
    events: List[Any] = Field(min_length=1)
    window_minutes: int = Field(default=15, ge=1, le=1440)


@router.get("/proposals")
def list_proposals(
    state: Optional[ProposalState] = Query(default=None),
    current_user: User = Depends(get_current_user),
):
    rows = proposals.listing(state.value if state else None)
    return {"proposals": _all_shown(current_user, rows)}


@router.post("/proposals", dependencies=_WRITE)
def paste_proposal(body: PasteRequest, current_user: User = Depends(get_current_user)):
    origin = {
        "source": "pasted",
        "case_id": body.case_id,
        "finding_id": body.finding_id,
    }
    if body.case_id:
        _require(current_user, _READ_CASES)
    if body.finding_id:
        _require(current_user, _READ_FINDINGS)
    with _answers():
        return _shown(
            current_user,
            proposals.create(
                sigma=body.sigma,
                actor=current_user.username,
                title=body.title,
                technique=body.technique,
                case_id=body.case_id,
                origin=origin,
            ),
        )


@router.post("/proposals/draft", dependencies=_WRITE)
async def draft_proposal(
    body: DraftRequest, current_user: User = Depends(get_current_user)
):
    if body.case_id:
        _require(current_user, _READ_CASES, _READ_FINDINGS)
    if body.finding_id:
        _require(current_user, _READ_FINDINGS)
    with _answers():
        try:
            return _shown(
                current_user,
                await proposals.draft_from_model(
                    actor=current_user.username,
                    case_id=body.case_id,
                    finding_id=body.finding_id,
                    technique=body.technique,
                    notes=body.notes,
                ),
            )
        except NoProviderConfigured as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/proposals/from-rule", dependencies=_WRITE)
def prove_rule(body: FromRuleRequest, current_user: User = Depends(get_current_user)):
    with _answers():
        return _shown(
            current_user, proposals.from_rule(body.rule_id, current_user.username)
        )


@router.get("/proposals/{proposal_id}")
def get_proposal(proposal_id: str, current_user: User = Depends(get_current_user)):
    with _answers():
        return _shown(current_user, proposals.get(proposal_id))


@router.get("/proposals/{proposal_id}/shadow-report")
def shadow_report(proposal_id: str, current_user: User = Depends(get_current_user)):
    with _answers():
        _may_read_replay(current_user, proposal_id)
        return proposals.shadow_report(proposal_id)


@router.post("/proposals/{proposal_id}/edit", dependencies=_WRITE)
def edit_proposal(
    proposal_id: str,
    body: EditRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        return _shown(
            current_user,
            proposals.edit(proposal_id, body.sigma, current_user.username, body.reason),
        )


@router.post("/proposals/{proposal_id}/lint", dependencies=_WRITE)
def lint_proposal(proposal_id: str, current_user: User = Depends(get_current_user)):
    with _answers():
        return _shown(current_user, proposals.lint(proposal_id, current_user.username))


@router.post("/proposals/{proposal_id}/replay", dependencies=_WRITE)
def replay_proposal(
    proposal_id: str,
    body: ReplayRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        _may_read_replay(current_user, proposal_id)
        return _shown(
            current_user,
            proposals.replay(
                proposal_id,
                current_user.username,
                event_ids=body.event_ids,
                window_days=body.window_days,
            ),
        )


@router.post("/proposals/{proposal_id}/tune", dependencies=_WRITE)
def tune_proposal(
    proposal_id: str,
    body: TuneRequest,
    current_user: User = Depends(get_current_user),
):
    try:
        exclusion = sigma_text.Exclusion(body.field, body.match, tuple(body.values))
    except sigma_text.NotARule as exc:
        raise HTTPException(status_code=422, detail={"message": str(exc)}) from exc
    with _answers():
        _may_read_replay(current_user, proposal_id)
        return _shown(
            current_user,
            proposals.tune(proposal_id, exclusion, current_user.username, body.reason),
        )


@router.post("/proposals/{proposal_id}/convert", dependencies=_WRITE)
def convert_proposal(
    proposal_id: str,
    body: ConvertRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        return _shown(
            current_user,
            proposals.convert(
                proposal_id,
                current_user.username,
                wanted=body.targets,
                pasted=body.pasted,
                accept_reason=body.accept_reason,
            ),
        )


@router.post("/proposals/{proposal_id}/shadow", dependencies=_WRITE)
def shadow_proposal(
    proposal_id: str,
    body: ReasonRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        return _shown(
            current_user,
            proposals.shadow(proposal_id, current_user.username, body.reason),
        )


@router.post("/proposals/{proposal_id}/live", dependencies=_WRITE)
def promote_proposal(
    proposal_id: str,
    body: ReasonRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        return _shown(
            current_user,
            proposals.promote(proposal_id, current_user.username, body.reason),
        )


@router.post("/proposals/{proposal_id}/reject", dependencies=_WRITE)
def reject_proposal(
    proposal_id: str,
    body: ReasonRequest,
    current_user: User = Depends(get_current_user),
):
    with _answers():
        return _shown(
            current_user,
            proposals.reject(proposal_id, current_user.username, body.reason),
        )


@router.get("/targets")
def list_targets():
    return {
        "targets": targets.availability(),
        "pysigma_installed": targets.pysigma_installed(),
        "not_installed": (
            None if targets.pysigma_installed() else targets.PYSIGMA_MISSING
        ),
        "measured": (
            "Share of 3,763 public SigmaHQ rules whose packaged file was well-formed, measured "
            "2026-10-21 with pySigma 0.11.23. No SIEM was available, so a valid file was not "
            "checked against a schema."
        ),
    }


@router.get("/coverage")
def get_coverage():
    return program.coverage()


@router.get("/rules")
def get_rules():
    return program.rule_health()


@router.get("/log-sources")
def get_log_sources():
    return program.log_sources()


@router.get("/threat-model")
def get_threat_model():
    return program.threat_model()


@router.put("/threat-model", dependencies=_WRITE)
def put_threat_model(
    body: ThreatModelRequest, current_user: User = Depends(get_current_user)
):
    with _answers():
        return program.save_threat_model(body.model_dump(), current_user.username)


@router.get("/red-team")
def get_red_team(current_user: User = Depends(get_current_user)):
    runs = program.red_team_runs()
    return (
        runs
        if _reads(current_user, _READ_FINDINGS)
        else program.without_citations(runs)
    )


@router.post("/red-team", dependencies=_WRITE)
async def post_red_team(
    body: RedTeamRequest, current_user: User = Depends(get_current_user)
):
    _require(current_user, _READ_FINDINGS)
    with _answers():
        return await program.run_red_team(
            name=body.name,
            events=body.events,
            actor=current_user.username,
            window_minutes=body.window_minutes,
        )
