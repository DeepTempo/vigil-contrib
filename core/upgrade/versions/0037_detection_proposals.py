"""Detection proposals and their append-only transitions."""

from core.upgrade.revision import run_sql

revision = "0037_detection_proposals"
down_revision = "0036_log_events"


def upgrade() -> None:
    run_sql(__file__)


def downgrade() -> None:
    raise NotImplementedError(
        "Vigil schema revisions only run forward; restore instead"
    )
