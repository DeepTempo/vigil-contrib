"""An incident is a case with 2 or more alerts, told as one story. Reads only."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth.permissions import APPROVE_PERMISSION, missing_permission
from core.incidents.read import NotAnIncident, list_incidents, read_story
from core.incidents.story import IncidentList, Story, Viewer
from core.routing import Auth, RouterMeta
from core.storage.models import User
from services.api.middleware.auth import get_current_user

CASES_READ = "cases.read"
# Steps are alert titles, so reading a story takes what reading those alerts takes.
FINDINGS_READ = "findings.read"
APPROVALS_READ = "ai_decisions.read"
NOT_FOUND = "Not found"


def _reader(user: User = Depends(get_current_user)) -> Viewer:
    """404, not 403, so a role without the reads cannot learn that a case id exists."""
    for permission in (CASES_READ, FINDINGS_READ):
        if missing_permission(user.user_id, permission):
            raise HTTPException(status_code=404, detail=NOT_FOUND)
    return Viewer(
        can_read_approvals=missing_permission(user.user_id, APPROVALS_READ) is None,
        can_decide=missing_permission(user.user_id, APPROVE_PERMISSION) is None,
    )


# Read by the role x route matrix test, as require_permission's are.
_reader.permission, _reader.unsafe_only = CASES_READ, False

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/incidents",
    tags=["incidents"],
    auth=Auth.REQUIRED,
)


@router.get("", response_model=IncidentList)
def get_incidents(
    status: Literal["open", "all"] = "open",
    limit: int = Query(50, ge=1, le=100),
    viewer: Viewer = Depends(_reader),
):
    return list_incidents(open_only=status == "open", limit=limit, viewer=viewer)


@router.get("/{case_id}", response_model=Story)
def get_incident(case_id: str, viewer: Viewer = Depends(_reader)):
    try:
        story = read_story(case_id, viewer)
    except NotAnIncident as refused:
        raise HTTPException(status_code=404, detail=str(refused))
    if story is None:
        raise HTTPException(status_code=404, detail=f"No case named {case_id}.")
    return story
