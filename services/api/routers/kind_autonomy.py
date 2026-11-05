"""Autonomy earned per kind of alert, beside the install-wide ceiling in autonomy.py.

A signed-in person adopts or revokes a close for one kind. The server decides eligibility
from people's own closures, so a request cannot supply evidence. Nothing here can contain,
block or approve anything.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.auth.auth_service import _is_service_account
from core.auth.permissions import deny_unless, missing_permission, permission_gate
from core.autonomy import policy
from core.response.ceiling import read_ceiling
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User
from services.api.middleware.auth import get_current_active_user

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/kind-autonomy",
    tags=["autonomy"],
    auth=Auth.REQUIRED,
)

_READ = [permission_gate("ai_autonomy.read")]
_READ_FINDINGS = "findings.read"
_READ_CLOSED = [*_READ, permission_gate(_READ_FINDINGS)]
_ADOPT = [permission_gate("ai_autonomy.write"), permission_gate(_READ_FINDINGS)]
_REVOKE = [permission_gate("ai_autonomy.stop")]
# Whoever may clear a noise mark may say this one was wrong. It only lowers autonomy.
_OVERTURN = [permission_gate("findings.write")]


class ReasonBody(BaseModel):
    reason: Optional[str] = None


class SettingBody(BaseModel):
    close_enabled: bool


def _person(user: User) -> str:
    if _is_service_account(user):
        raise HTTPException(
            status_code=403,
            detail="Only a signed-in person can change what Vigil may do on its own",
        )
    return user.principal_id or str(user.user_id)


def _refuse_while_stopped() -> None:
    try:
        stopped = read_ceiling().stopped
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="Could not read the autonomy ceiling"
        ) from exc
    if stopped:
        raise HTTPException(status_code=409, detail="Stopped: resume first")


def _reason(body: Optional[ReasonBody], default: str) -> str:
    return ((body.reason if body else None) or "").strip() or default


def _reads_findings(user: User, session: UnitOfWorkSession) -> bool:
    return missing_permission(user.user_id, _READ_FINDINGS, session) is None


@router.get("", dependencies=_READ)
def list_kinds(
    session: UnitOfWorkSession,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    view = policy.kinds_view(session)
    return (
        view
        if _reads_findings(current_user, session)
        else policy.policy_only_view(view)
    )


@router.put("/settings", dependencies=_READ)
def put_setting(
    body: SettingBody,
    session: UnitOfWorkSession,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, bool]:
    """Whether the daemon acts on adopted policies. On is a raise; off is a stop."""
    _person(current_user)
    permission = "ai_autonomy.write" if body.close_enabled else "ai_autonomy.stop"
    deny_unless(current_user.user_id, permission, session)
    if body.close_enabled:
        _refuse_while_stopped()
    if not policy.set_close_enabled(body.close_enabled, str(current_user.user_id)):
        raise HTTPException(status_code=500, detail="Failed to save the setting")
    return {"close_enabled": body.close_enabled}


@router.post("/{key}/adopt", dependencies=_ADOPT)
def adopt_kind(
    key: str,
    session: UnitOfWorkSession,
    body: Optional[ReasonBody] = None,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    actor = _person(current_user)
    _refuse_while_stopped()
    try:
        return policy.adopt(
            session, key, actor, _reason(body, "A person adopted close for this kind.")
        )
    except policy.KindNotFound as exc:
        raise HTTPException(status_code=404, detail="No kind by that key") from exc
    except policy.NotEligible as exc:
        raise HTTPException(status_code=409, detail=f"Not eligible. {exc}") from exc


@router.post("/{key}/revoke", dependencies=_REVOKE)
def revoke_kind(
    key: str,
    session: UnitOfWorkSession,
    body: Optional[ReasonBody] = None,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    actor = _person(current_user)
    try:
        return policy.revoke(
            session, key, actor, _reason(body, "A person revoked this adoption.")
        )
    except policy.KindNotFound as exc:
        raise HTTPException(status_code=404, detail="No kind by that key") from exc
    except policy.NotClosing as exc:
        raise HTTPException(
            status_code=409, detail="This kind is not on close"
        ) from exc


@router.get("/{key}/events", dependencies=_READ)
def kind_events(
    key: str,
    session: UnitOfWorkSession,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    events = policy.events_view(session, key)
    if not _reads_findings(current_user, session):
        events = policy.policy_only_events(events)
    return {"events": events}


@router.get("/{key}/closed", dependencies=_READ_CLOSED)
def kind_closed(
    key: str,
    session: UnitOfWorkSession,
    limit: int = Query(25, ge=1, le=200),
    sample: bool = Query(False),
) -> Dict[str, Any]:
    return policy.closed_view(session, key, limit=limit, sample=sample)


@router.post("/{key}/closed/{finding_id}/overturn", dependencies=_OVERTURN)
def overturn_closure(
    key: str,
    finding_id: str,
    session: UnitOfWorkSession,
    body: Optional[ReasonBody] = None,
    current_user: User = Depends(get_current_active_user),
) -> Dict[str, Any]:
    actor = _person(current_user)
    try:
        return policy.overturn(
            session,
            key,
            finding_id,
            actor,
            current_user.username,
            _reason(body, "A person overturned a closure by this policy."),
        )
    except (policy.KindNotFound, policy.NotClosedByPolicy) as exc:
        raise HTTPException(
            status_code=404, detail="This policy did not close that alert"
        ) from exc
