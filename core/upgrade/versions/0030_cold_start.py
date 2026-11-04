"""Day-one cold start: a run, its alert snapshots and its filtered tickets."""

from core.upgrade.revision import run_sql

revision = "0030_cold_start"
down_revision = "0029_detection_rule_stages"


def upgrade() -> None:
    run_sql(__file__)


def downgrade() -> None:
    raise NotImplementedError(
        "Vigil schema revisions only run forward; restore instead"
    )
