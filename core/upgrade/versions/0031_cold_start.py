"""Day-one cold start: a run, its alert snapshots and its filtered tickets."""

from core.upgrade.revision import run_sql

revision = "0031_cold_start"
down_revision = "0030_drop_settings_keys"


def upgrade() -> None:
    run_sql(__file__)


def downgrade() -> None:
    raise NotImplementedError(
        "Vigil schema revisions only run forward; restore instead"
    )
