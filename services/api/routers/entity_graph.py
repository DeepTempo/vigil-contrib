"""Who talks to whom in the stored logs: roles, blocks, zero-trust gaps, a case's path."""

from typing import Annotated, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth.current_user import get_current_user
from core.auth.permissions import deny_unless, permission_gate
from core.entity_graph.store import MAX_HOURS, CaseNotFound, entity_graph_payload
from core.routing import Auth, RouterMeta
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/entity-graph",
    tags=["entity-graph"],
    auth=Auth.REQUIRED,
)


@router.get("", dependencies=[permission_gate("findings.read")])
def get_entity_graph(
    current_user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=MAX_HOURS),
    case_id: Optional[str] = Query(None, max_length=50),
) -> dict[str, Any]:
    """The graph over the newest stored flows in the window, up to the cap it reports.

    A plain ``def``: FastAPI runs it on a worker thread, so the build stays off the event
    loop. ``case_id`` also reads the case, so it takes that case's own permission.
    """
    if case_id:
        deny_unless(current_user.user_id, "cases.read")
    try:
        return entity_graph_payload(hours, case_id)
    except CaseNotFound:
        raise HTTPException(status_code=404, detail="Case not found") from None
