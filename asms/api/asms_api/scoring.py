"""Security-score calculation.

Mirrors the formula in `asms/db/schema.sql` (vw_org_posture):

    score = GREATEST(0, 100 - (critical*20 + high*8 + medium*3 + low*1))

Only ``status='open'`` findings contribute. ``fixed`` and ``false_positive``
are tracked but excluded from the score so a remediated finding doesn't
keep dragging the score down.
"""

from __future__ import annotations

from asms_api.models import Severity

WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 8,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def compute_score(counts_by_severity: dict[Severity, int]) -> int:
    """Return an int in [0, 100]."""
    penalty = sum(
        WEIGHTS[sev] * counts_by_severity.get(sev, 0) for sev in Severity
    )
    return max(0, min(100, 100 - penalty))
