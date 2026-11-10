"""Experimental risk score. See docs/RISK_SCORING.md.

IMPORTANT: this is a simple, rule-based *prioritisation aid* for ordering events. It is not a
probability of compromise and not a verdict. It is separate from `severity`, which is the
event source's own label. Phase 4 kept these weights; an incident takes the highest score of its events.

score = severity points + source points + repeat-indicator bonus, limited to 0..100.
"""
from app.enums import Severity, Source

SEVERITY_POINTS = {
    Severity.info: 0,
    Severity.low: 10,
    Severity.medium: 25,
    Severity.high: 40,
    Severity.critical: 55,
}
SOURCE_POINTS = {
    Source.honeypot: 15,   # someone contacted a trap that no legitimate user should touch
    Source.file: 10,
    Source.domain: 5,
    Source.network: 5,
}
REPEAT_POINTS_EACH = 5     # per earlier event that mentioned the same indicator
REPEAT_CAP = 20            # the bonus never exceeds this
MAX_SCORE = 100


def compute_risk(severity: Severity, source: Source, prior_sightings: int) -> tuple[int, list[dict]]:
    """Return (score, factors) where factors explain every point, e.g. {"rule": "source:honeypot", "points": 15}.

    `prior_sightings` is the number of EARLIER events that already mentioned the most-seen
    indicator of this event. The event being scored is not counted, so the first sighting
    gets +0, the second +5, the third +10 and so on, up to +20.
    """
    factors = [
        {"rule": f"severity:{severity.value}", "points": SEVERITY_POINTS[severity]},
        {"rule": f"source:{source.value}", "points": SOURCE_POINTS[source]},
    ]
    repeat = min(max(prior_sightings, 0) * REPEAT_POINTS_EACH, REPEAT_CAP)
    if repeat > 0:
        factors.append({"rule": "repeat_indicator", "points": repeat})

    score = max(0, min(MAX_SCORE, sum(f["points"] for f in factors)))
    return score, factors
