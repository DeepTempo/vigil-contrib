"""Real alerts by kind, with what happened to them."""

from fastapi import APIRouter, Query

from core.auth.permissions import permission_gate
from core.incidents.alert_kinds import MAX_HOURS, AlertTriage, read_alert_triage
from core.routing import Auth, RouterMeta

router = APIRouter()
router.dependencies.append(permission_gate("findings.read"))

ROUTER_META = RouterMeta(
    prefix="/api/alert-triage",
    tags=["alert-triage"],
    auth=Auth.REQUIRED,
)


@router.get("", response_model=AlertTriage)
def get_alert_triage(hours: int = Query(24, ge=1, le=MAX_HOURS)):
    return read_alert_triage(hours)
