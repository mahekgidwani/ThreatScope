"""Experimental risk score: severity points + source points + repeat-indicator bonus.

Expected numbers are written out independently of the module's own tables on purpose.
`prior_sightings` = earlier events that already mentioned the event's most-seen indicator;
the event being scored is NOT counted, so the first sighting gets no bonus.
"""
import itertools
import json

import pytest

from app.enums import Severity, Source
from app.services import risk_scoring
from app.services.risk_scoring import compute_risk

SEVERITY_POINTS = {"info": 0, "low": 10, "medium": 25, "high": 40, "critical": 55}
SOURCE_POINTS = {"honeypot": 15, "file": 10, "domain": 5, "network": 5}
ALL = list(itertools.product(Severity, Source))


def repeat_points(factors) -> int:
    return sum(f["points"] for f in factors if f["rule"] == "repeat_indicator")


@pytest.mark.parametrize("severity,source", ALL)
def test_first_sighting_score_is_severity_plus_source_points(severity, source):
    score, _ = compute_risk(severity, source, 0)
    assert score == SEVERITY_POINTS[severity.value] + SOURCE_POINTS[source.value]


@pytest.mark.parametrize("severity,source,prior,expected", [
    (Severity.info, Source.domain, 0, 5),
    (Severity.high, Source.honeypot, 0, 55),        # 40 + 15 + 0
    (Severity.critical, Source.honeypot, 0, 70),    # 55 + 15 + 0
    (Severity.low, Source.file, 1, 25),             # 10 + 10 + 5
    (Severity.low, Source.file, 10, 40),            # 10 + 10 + 20 (capped)
    (Severity.critical, Source.honeypot, 4, 90),    # the highest score possible
])
def test_worked_examples(severity, source, prior, expected):
    assert compute_risk(severity, source, prior)[0] == expected


@pytest.mark.parametrize("prior,bonus", [(0, 0), (1, 5), (2, 10), (3, 15), (4, 20), (5, 20), (6, 20)])
def test_repeat_bonus_schedule(prior, bonus):
    _, factors = compute_risk(Severity.low, Source.file, prior)
    assert repeat_points(factors) == bonus


def test_first_sighting_has_no_repeat_factor_at_all():
    score, factors = compute_risk(Severity.high, Source.honeypot, 0)
    assert "repeat_indicator" not in [f["rule"] for f in factors]
    assert score == sum(f["points"] for f in factors) == 55


def test_second_sighting_adds_5_and_third_adds_10():
    first = compute_risk(Severity.high, Source.honeypot, 0)[0]
    second = compute_risk(Severity.high, Source.honeypot, 1)[0]
    third = compute_risk(Severity.high, Source.honeypot, 2)[0]
    assert (second - first, third - first) == (5, 10)


@pytest.mark.parametrize("prior", [-1, -50])
def test_negative_prior_counts_as_zero(prior):
    assert compute_risk(Severity.high, Source.honeypot, prior) == compute_risk(Severity.high, Source.honeypot, 0)


def test_huge_prior_is_capped():
    assert repeat_points(compute_risk(Severity.low, Source.file, 10**9)[1]) == 20


@pytest.mark.parametrize("severity,source", ALL)
def test_score_is_in_range_and_equals_the_sum_of_its_factors(severity, source):
    for prior in range(0, 9):
        score, factors = compute_risk(severity, source, prior)
        assert 0 <= score <= 100
        assert score == sum(f["points"] for f in factors)


def test_factor_names_and_shape():
    score, factors = compute_risk(Severity.medium, Source.network, 2)
    assert factors == [
        {"rule": "severity:medium", "points": 25},
        {"rule": "source:network", "points": 5},
        {"rule": "repeat_indicator", "points": 10},
    ]
    assert score == 40
    assert json.loads(json.dumps(factors)) == factors   # plain JSON, safe to store


def test_zero_point_severity_is_still_explained():
    _, factors = compute_risk(Severity.info, Source.domain, 0)
    assert factors[0] == {"rule": "severity:info", "points": 0}


def test_constants_match_the_documented_weights():
    assert {k.value: v for k, v in risk_scoring.SEVERITY_POINTS.items()} == SEVERITY_POINTS
    assert {k.value: v for k, v in risk_scoring.SOURCE_POINTS.items()} == SOURCE_POINTS
    assert (risk_scoring.REPEAT_POINTS_EACH, risk_scoring.REPEAT_CAP) == (5, 20)
