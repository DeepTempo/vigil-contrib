"""GET /api/workflows/custom: the saved custom workflows, as the builder reopens them.

Routers mount in order of their short names (services/api/discovery.py), so
``custom_reads`` comes before ``workflows``, whose ``/workflows/{id}`` would
otherwise take these paths.
"""

from fastapi import APIRouter, Depends, HTTPException

from core.auth.permissions import permission_gate
from core.deps import provide_custom_workflows
from core.routing import Auth, RouterMeta
from core.workflows.custom_workflow_service import CustomWorkflowService

router = APIRouter()
router.dependencies.append(permission_gate("automation.read"))

ROUTER_META = RouterMeta(
    prefix="/api/workflows/custom", tags=["workflows"], auth=Auth.REQUIRED
)


@router.get("")
async def list_custom_workflows(
    active_only: bool = True,
    service: CustomWorkflowService = Depends(provide_custom_workflows),
):
    """List database-backed custom workflows."""
    rows = service.list(active_only=active_only)
    return {"workflows": rows, "count": len(rows)}


@router.get("/{workflow_id}")
async def get_custom_workflow(
    workflow_id: str,
    service: CustomWorkflowService = Depends(provide_custom_workflows),
):
    """Fetch a single custom workflow."""
    wf = service.get(workflow_id)
    if not wf:
        raise HTTPException(
            status_code=404, detail=f"Custom workflow not found: {workflow_id}"
        )
    return wf
