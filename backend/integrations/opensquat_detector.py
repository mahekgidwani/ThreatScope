# SPDX-License-Identifier: GPL-3.0-only
"""Domain look-alike detection, adapted from openSquat 2.3.0 -> ThreatScope `domain` events.

Original work: openSquat, (c) Andre Tenreiro, GNU GPL v3 -- https://github.com/atenreiro/opensquat
Adapted functions: `levenshtein` (opensquat/validations.py, unchanged), `check_homograph` and
`homograph_to_latin` (opensquat/homograph.py), and the decision order of
`SquattingDetector._process_levenshtein` (opensquat/squatting_detector.py). ThreatScope is also
GPL-3.0 (see LICENSE); modifications are listed in third_party/NOTICE.md and below.

Modifications made for ThreatScope
  1. `find_squatting` returns structured `Finding` objects instead of printing coloured text.
     The same three outcomes exist: similarity (edit distance <= confidence level), homograph
     (the same, but the label had look-alike characters) and keyword contained in the domain.
  2. Punycode (xn--) names are decoded to Unicode before the homograph check. The original check
     looks at the label as written, so on a feed that stores IDNs as punycode (the openSquat
     feed does) it reports "not a homograph" for every one of them.
  3. `homograph_to_latin` is lower-cased and deterministic. The original joins the *set* of ASCII
     candidates of a character, whose order changes between runs, and keeps upper case, so it
     could never equal a lower-case keyword.
  4. The homoglyph tables are loaded once, not on every call (speed only).
  5. Keywords and domains are validated and normalised first (see `clean_keyword`,
     `prepare_domain`); keywords shorter than 3 characters are refused (they match almost anything);
     an optional `trusted` set skips a brand's own domains.
Not used from openSquat: feed download, DNS/port checks, certificate transparency, VirusTotal,
the paid API, and the doppelganger mode (they need network access or keys).

What a finding means: a domain whose NAME resembles a keyword. It is a lead to check, not proof of
abuse. Nothing here looks at DNS, web content or certificates, so events never claim more.
"""
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

import homoglyphs as hg
import idna
from confusable_homoglyphs import confusables

from app.schemas.event import normalise_domain
from integrations.client import stable_event_id

DETECTOR_ID = "opensquat-derived-1"
MIN_KEYWORD_LENGTH, MAX_KEYWORD_LENGTH = 3, 63
MAX_DOMAIN_TEXT = 300
NOTE = ("Detection finding only, not a confirmed threat: the domain NAME resembles a keyword. "
        "No DNS, content or certificate check was made.")

# Same labels as openSquat's SquattingDetector.confidence.
CONFIDENCE = {0: "very high confidence", 1: "high confidence", 2: "medium confidence",
              3: "low confidence", 4: "very low confidence"}
EVENT_TYPES = {"similarity": "domain_similarity", "homograph": "domain_homograph",
               "keyword_contained": "domain_keyword_match"}
# Nothing is verified, so no finding is rated above medium.
SEVERITY_BY_DISTANCE = {0: "medium", 1: "medium", 2: "low", 3: "info", 4: "info"}


# ---- openSquat functions -----------------------------------------------------------------

def levenshtein(keyword, domain, threshold=None):
    """Compute Levenshtein distance using native Python. (openSquat, unchanged.)

    When threshold is provided, applies early exit optimizations:
    - Skips computation if length difference exceeds threshold
    - Stops mid-computation if no result can beat threshold
    Returns threshold + 1 for values that exceed the threshold.
    """
    len0 = len(keyword)
    len1 = len(domain)

    if threshold is not None and abs(len0 - len1) > threshold:
        return threshold + 1

    if keyword == domain:
        return 0
    if len0 == 0:
        return len1
    if len1 == 0:
        return len0

    v0 = list(range(len1 + 1))
    v1 = [0] * (len1 + 1)

    for i in range(len0):
        v1[0] = i + 1
        char_i = keyword[i]
        row_min = v1[0]
        for j in range(len1):
            cost = 0 if char_i == domain[j] else 1
            val = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            v1[j + 1] = val
            if val < row_min:
                row_min = val
        if threshold is not None and row_min > threshold:
            return threshold + 1
        v0, v1 = v1, v0

    return v0[len1]


def check_homograph(domain):
    """True if the label contains confusable (look-alike) characters. (openSquat's check.)"""
    return bool(confusables.is_dangerous(domain))


@lru_cache(maxsize=1)
def _homoglyphs():
    return hg.Homoglyphs(languages={"en"}, strategy=hg.STRATEGY_LOAD)


def homograph_to_latin(domain):
    """Convert look-alike characters to Latin ones (see modification 3)."""
    homoglyphs = _homoglyphs()
    converted = []
    for char in domain:
        if hg.Categories.detect(char) != "LATIN":
            converted.append("".join(sorted(homoglyphs.to_ascii(char))))
        else:
            converted.append(char)
    return "".join(converted).lower()


# ---- cleaning input --------------------------------------------------------------------------

def clean_keyword(raw: str) -> str | None:
    """A usable lower-case keyword, or None for blanks, comments and unusable text."""
    text = unicodedata.normalize("NFC", raw.strip()).lower()
    if not text or text.startswith("#") or not MIN_KEYWORD_LENGTH <= len(text) <= MAX_KEYWORD_LENGTH:
        return None
    if "." in text or any(ch.isspace() or not ch.isprintable() for ch in text):
        return None
    return text


def prepare_domain(raw: str) -> str | None:
    """The API's spelling of a domain (lower case, punycode), or None if the line is not a
    usable domain (blank, comment, no dot, IP address, invalid name)."""
    text = raw.strip()
    if not text or text.startswith("#") or len(text) > MAX_DOMAIN_TEXT:
        return None
    try:
        domain = normalise_domain(text)   # the API's own rules, so stored values always agree
    except ValueError:
        return None
    return domain if "." in domain else None


# ---- detection -------------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    keyword: str
    domain: str                   # ASCII/punycode, as the API stores it
    kind: str                     # similarity | homograph | keyword_contained
    distance: int | None          # edit distance (None for keyword_contained)
    confidence: str | None        # openSquat's label for that distance
    compared_label: str           # first label as compared (look-alikes converted for homographs)
    domain_unicode: str           # the domain as a person would see it
    threshold: int                # the confidence level this run used


def _unicode_form(domain: str) -> str:
    try:
        return idna.decode(domain)
    except Exception:  # noqa: BLE001 - any failure means "keep the ASCII form"
        return domain


def find_squatting(keywords, domains, confidence_level: int = 1, trusted=frozenset()):
    """Yield a Finding for each (keyword, domain) pair that openSquat's rules would report.

    `domains` must already be in API spelling (`prepare_domain`). Like the original, only the
    first label is compared for similarity, and `keyword in <whole domain>` is the fallback.
    """
    keywords = list(dict.fromkeys(keywords))
    for domain in domains:
        if domain in trusted:
            continue
        shown = _unicode_form(domain)
        label = shown.split(".")[0].lower()
        homograph = check_homograph(label)
        compared = homograph_to_latin(label) if homograph else label
        for keyword in keywords:
            distance = levenshtein(keyword, compared, confidence_level)
            if distance <= confidence_level:
                yield Finding(keyword, domain, "homograph" if homograph else "similarity", distance,
                              CONFIDENCE.get(distance, "unknown"), compared, shown, confidence_level)
            elif keyword in shown:
                yield Finding(keyword, domain, "keyword_contained", None, None, compared, shown,
                              confidence_level)


# ---- the event -------------------------------------------------------------------------------

def _describe(finding: Finding) -> str:
    if finding.kind == "keyword_contained":
        what = f"'{finding.domain}' contains the keyword '{finding.keyword}'"
    else:
        plural = "" if finding.distance == 1 else "s"
        what = (f"'{finding.domain}' is {finding.distance} edit{plural} away from the keyword "
                f"'{finding.keyword}' ({finding.confidence}"
                + ("; look-alike characters replaced, IDN homograph)" if finding.kind == "homograph"
                   else "; possible typosquat)"))
    return f"{what}. Detection finding only; not a confirmed threat."


def build_event(finding: Finding, now: datetime | None = None) -> dict:
    """The dict to send with ThreatScopeClient.submit_event (shape defined by the API's EventIn).

    `external_event_id` depends only on keyword + domain, so re-running over the same feed finds
    the same events and the API rejects them as duplicates."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    severity = "low" if finding.distance is None else SEVERITY_BY_DISTANCE.get(finding.distance, "info")
    metadata = {
        "detector": DETECTOR_ID, "keyword": finding.keyword, "detection": finding.kind,
        "edit_distance": finding.distance, "confidence": finding.confidence,
        "confidence_level_setting": finding.threshold, "compared_label": finding.compared_label,
        "verified": False, "note": NOTE,
    }
    if finding.domain_unicode != finding.domain:
        metadata["domain_unicode"] = finding.domain_unicode
    return {
        "external_event_id": stable_event_id("domain", finding.keyword, finding.domain),
        "source": "domain",
        "event_type": EVENT_TYPES[finding.kind],
        "occurred_at": now,
        "domain": finding.domain,
        "severity": severity,
        "description": _describe(finding),
        "metadata": metadata,
    }
