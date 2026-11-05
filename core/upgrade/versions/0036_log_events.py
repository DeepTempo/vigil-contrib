"""One event store for the Logs page, the entity graph and rule replay."""

from core.upgrade.revision import run_sql

revision = "0036_log_events"
down_revision = "0035_cold_start"


def upgrade() -> None:
    run_sql(__file__)


def downgrade() -> None:
    raise NotImplementedError(
        "Vigil schema revisions only run forward; restore instead"
    )
