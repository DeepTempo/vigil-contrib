"""The saved-workflow reads must mount before ``GET /api/workflows/{workflow_id}``."""

from services.api.discovery import iter_router_modules


def test_custom_reads_mount_before_the_parameterized_workflow_route():
    mounted = iter_router_modules()
    assert mounted.index("custom_reads") < mounted.index("workflows")
