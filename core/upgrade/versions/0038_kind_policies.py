"""Per alert kind autonomy policy and its append-only history."""

from core.upgrade.revision import run_sql

revision = "0038_kind_policies"
down_revision = "0037_detection_proposals"


def upgrade() -> None:
    run_sql(__file__)


def downgrade() -> None:
    raise NotImplementedError(
        "Vigil schema revisions only run forward; restore instead"
    )
