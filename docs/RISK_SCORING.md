# Risk scoring (experimental)

**What it is.** `risk_score` is a number from 0 to 100 that the server calculates for every event when it is
stored. It exists to help sort a long list of events so the ones most worth a look come first.

**What it is not.** It is an *experimental prioritisation score*. It is not a probability that a system was
compromised, not a verdict, and not a replacement for an analyst's judgement. The weights are simple, hand-chosen
and expected to change after the correlation work in Phase 4.

**Separate from `severity`.** `severity` (info / low / medium / high / critical) is the label the event's source
gave it. `risk_score` is ThreatScope's own number. Clients cannot send a `risk_score`; the API rejects it.

Code: `backend/app/services/risk_scoring.py` (`compute_risk`). Tests: `backend/tests/unit/test_risk_scoring.py`.

## The rule

```
risk_score = severity points + source points + repeat-indicator bonus      (never below 0, never above 100)
```

| Part | Value |
|---|---|
| Severity points | info 0 · low 10 · medium 25 · high 40 · critical 55 |
| Source points | honeypot 15 · file 10 · domain 5 · network 5 |
| Repeat-indicator bonus | +5 for every **earlier** event that mentioned the same indicator, at most +20 |

Why these parts:
- *Severity* is the strongest signal because the source has looked at the event.
- *Source*: contact with a honeypot is unsolicited by definition (nobody legitimate should touch it), so it gets the most.
- *Repeat bonus*: an IP, domain, URL or file hash that keeps coming back deserves more attention. If an event mentions
  several indicators, the most-seen one decides.

## The repeat bonus counts only EARLIER events

The event being scored is never counted as one of its own earlier sightings.

| Event number for the same indicator | Earlier events | Bonus |
|---|---|---|
| 1st | 0 | +0 |
| 2nd | 1 | +5 |
| 3rd | 2 | +10 |
| 4th | 3 | +15 |
| 5th and later | 4 or more | +20 (cap) |

## Worked examples

| Event | Severity | Source | Repeat | Score |
|---|---|---|---|---|
| First `high` honeypot attack from a new IP | 40 | 15 | 0 | **55** |
| Same IP attacks again (2nd event) | 40 | 15 | +5 | **60** |
| Same IP, 3rd event | 40 | 15 | +10 | **65** |
| First `critical` honeypot attack | 55 | 15 | 0 | **70** |
| `critical` honeypot, indicator seen 4+ times before | 55 | 15 | +20 | **90** (the highest possible) |
| First `info` domain match | 0 | 5 | 0 | **5** |
| `low` file analysis, indicator seen 10 times before | 10 | 10 | +20 | **40** |

## Explanation stored with every event

Each event keeps `risk_factors`, the list of lines that were added up, for example for the second `high` honeypot
event from the same IP:

```json
[
  {"rule": "severity:high",    "points": 40},
  {"rule": "source:honeypot",  "points": 15},
  {"rule": "repeat_indicator", "points": 5}
]
```

The `repeat_indicator` line appears only when the bonus is above 0. The severity line is always present, even at 0 points.

## Behaviour under concurrency

The sighting count is increased with one atomic database statement that also returns the new count. Two events
arriving at the same moment therefore always see different counts, and the bonus is exact (verified by a test that
fires 8 simultaneous events at PostgreSQL).

## Known limits

- The score is calculated once, when the event is stored. Events stored earlier do not change when an indicator
  later becomes common.
- Only counts matter; the age of earlier sightings does not.
- The weights are not calibrated against real data.
- Phase 4 (correlation and incidents) is expected to refine or replace these rules.
