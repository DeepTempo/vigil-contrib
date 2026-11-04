"""A run's lifecycle, as DESIGN.md states it."""

from itertools import product

import pytest

from core.storage.models import ColdStartRun
from core.storage.models.cold_start import (
    TRANSITIONS,
    InvalidTransition,
    RunStatus,
)

pytestmark = pytest.mark.unit

C, J, R, L, F = (
    RunStatus.COLLECTING,
    RunStatus.JUDGING,
    RunStatus.READY,
    RunStatus.LIVE,
    RunStatus.FAILED,
)
ALLOWED = {(C, J), (C, F), (J, R), (J, F), (R, J), (R, L), (R, F), (L, R)}


@pytest.mark.parametrize("current, wanted", list(product(RunStatus, RunStatus)))
def test_every_pair_of_statuses_is_allowed_or_refused(current, wanted):
    run = ColdStartRun(status=current)
    if (current, wanted) in ALLOWED:
        run.move_to(wanted)
        assert run.status is wanted
    else:
        with pytest.raises(InvalidTransition):
            run.move_to(wanted)
        assert run.status is current


def test_the_table_names_every_status_and_failed_is_terminal():
    assert set(TRANSITIONS) == set(RunStatus)
    assert TRANSITIONS[F] == frozenset()
