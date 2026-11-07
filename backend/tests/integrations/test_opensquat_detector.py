"""The openSquat-derived detection core: parity with the original, plus the documented changes."""
import subprocess
import sys
import time

import pytest

from integrations.opensquat_detector import (
    Finding, check_homograph, clean_keyword, find_squatting, homograph_to_latin, levenshtein, prepare_domain,
)

CYRILLIC_A = "а"                       # looks exactly like Latin 'a'
HOMOGRAPH_PAYPAL = f"p{CYRILLIC_A}ypal"      # 'pаypal'
HOMOGRAPH_PUNYCODE = "xn--pypal-4ve.com"     # how the API (and DNS) spell 'pаypal.com'


def findings(keywords, domains, confidence=1, trusted=()):
    return list(find_squatting(keywords, domains, confidence_level=confidence, trusted=set(trusted)))


# ---- parity with openSquat's own functions ---------------------------------------------

@pytest.mark.parametrize("keyword, domain, expected", [
    ("netflix", "netflix123.com", 7),     # the two cases in openSquat's own test-suite
    ("netflix", "888888888888.com", 16),
    ("kitten", "sitting", 3),
    ("paypal", "paypal", 0),
    ("", "abc", 3),
    ("abc", "", 3),
])
def test_levenshtein_matches_the_original(keyword, domain, expected):
    assert levenshtein(keyword, domain) == expected


def test_levenshtein_threshold_returns_threshold_plus_one():
    assert levenshtein("paypal", "completelydifferent", 2) == 3     # length gap alone is enough
    assert levenshtein("paypal", "zzzzzz", 2) == 3                  # stops mid-computation
    assert levenshtein("paypal", "paypa1", 2) == 1


def test_check_homograph():
    assert check_homograph(HOMOGRAPH_PAYPAL) is True
    assert check_homograph("paypal") is False
    assert check_homograph("paypa1") is False                       # digits are not a homograph


def test_the_original_check_cannot_see_punycode():
    """Why the adapter decodes xn-- names first: the feed holds punycode, and on punycode the
    original check says 'not dangerous'."""
    assert check_homograph("xn--pypal-4ve") is False


def test_homograph_to_latin():
    assert homograph_to_latin(HOMOGRAPH_PAYPAL) == "paypal"
    assert homograph_to_latin(f"gооgle") == "google"


def test_homograph_to_latin_is_lowercase_and_deterministic_across_processes():
    code = ("from integrations.opensquat_detector import homograph_to_latin;"
            "print(homograph_to_latin('g\\u043e\\u043egle1l2'))")
    outputs = set()
    for seed in ("1", "2", "3", "99"):
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              env={"PYTHONHASHSEED": seed, "PATH": "/usr/local/bin:/usr/bin:/bin"}, cwd="/app")
        assert done.returncode == 0, done.stderr
        outputs.add(done.stdout.strip())
    assert len(outputs) == 1
    assert outputs.pop().islower()


# ---- cleaning input -------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("paypal", "paypal"), ("  PayPal \n", "paypal"), ("münchen", "münchen"),
    ("", None), ("   ", None), ("# comment", None), ("ab", None),            # too short
    ("pay pal", None), ("paypal.com", None), ("x" * 64, None),
    ("pay\x00pal", None), ("pay\x07pal", None), ("pay‮pal", None),     # NUL, control, bidi override
])
def test_clean_keyword(raw, expected):
    assert clean_keyword(raw) == expected


@pytest.mark.parametrize("raw, expected", [
    ("example.com", "example.com"), ("  EXAMPLE.COM.  ", "example.com"),
    (f"p{CYRILLIC_A}ypal.com", HOMOGRAPH_PUNYCODE),
    ("", None), ("# comment", None), ("localhost", None),              # no dot
    ("not a domain.com", None), ("-bad-.com", None), ("1.2.3.4", None),
    ("a" * 300 + ".com", None), ("x\x00y.com", None), ("http://example.com", None),
])
def test_prepare_domain(raw, expected):
    assert prepare_domain(raw) == expected


# ---- detection ------------------------------------------------------------------------------

def test_same_name_other_tld_is_distance_zero():
    [hit] = findings(["paypal"], ["paypal.xyz"])
    assert (hit.keyword, hit.domain, hit.kind, hit.distance) == ("paypal", "paypal.xyz", "similarity", 0)
    assert hit.confidence == "very high confidence"


@pytest.mark.parametrize("domain", ["paypa1.com", "paypall.com", "pypal.com", "paypa.com", "peypal.com"])
def test_one_edit_typos(domain):
    [hit] = findings(["paypal"], [domain])
    assert hit.kind == "similarity" and hit.distance == 1 and hit.confidence == "high confidence"


def test_keyword_inside_a_longer_name():
    [hit] = findings(["paypal"], ["paypal-secure-login.com"])
    assert hit.kind == "keyword_contained"
    assert hit.distance is None and hit.confidence is None


def test_unrelated_domains_are_ignored():
    assert findings(["paypal"], ["example.com", "wikipedia.org", "a-b-c.net"]) == []


def test_the_confidence_level_is_the_distance_limit():
    assert findings(["paypal"], ["pyapal.com"], confidence=1) == []         # two edits away
    [hit] = findings(["paypal"], ["pyapal.com"], confidence=2)
    assert hit.distance == 2 and hit.confidence == "medium confidence"


def test_only_the_first_label_is_compared_for_similarity_like_the_original():
    [hit] = findings(["paypal"], ["www.paypal.com"])        # 'www' is the first label, so not 'similarity'...
    assert hit.kind == "keyword_contained"                  # ...but the keyword is inside the whole name
    assert findings(["paypal"], ["www.paypa1.com"]) == []   # a typo in a later label is not seen


def test_punycode_homograph_is_found():
    [hit] = findings(["paypal"], [HOMOGRAPH_PUNYCODE])
    assert hit.kind == "homograph" and hit.distance == 0
    assert hit.domain == HOMOGRAPH_PUNYCODE
    assert hit.compared_label == "paypal"
    assert hit.domain_unicode == f"p{CYRILLIC_A}ypal.com"


def test_unrelated_homograph_is_ignored():
    assert findings(["paypal"], ["xn--pple-43d.com"]) == []                 # 'аpple'


def test_a_normal_idn_that_is_not_a_homograph():
    assert findings(["paypal"], ["xn--mnchen-3ya.de"]) == []                # münchen.de


def test_trusted_domains_are_skipped_exactly():
    assert findings(["paypal"], ["paypal.com"], trusted={"paypal.com"}) == []
    assert len(findings(["paypal"], ["paypal.xyz"], trusted={"paypal.com"})) == 1


def test_one_domain_can_match_several_keywords():
    hits = findings(["paypal", "paypa"], ["paypal.xyz"])
    assert sorted(h.keyword for h in hits) == ["paypa", "paypal"]


def test_input_case_does_not_matter():
    assert len(findings(["paypal"], ["PAYPAL.XYZ".lower()])) == 1


def test_findings_are_plain_data():
    [hit] = findings(["paypal"], ["paypal.xyz"])
    assert isinstance(hit, Finding)
    with pytest.raises(AttributeError):
        hit.domain = "other.com"          # frozen


def test_large_feed_is_scanned_in_reasonable_time():
    domains = [f"site{i}-{'abcdefghij'[i % 10]}.com" for i in range(20_000)]
    keywords = ["paypal", "amazon", "google", "facebook", "microsoft"]
    started = time.perf_counter()
    findings(keywords, domains)
    assert time.perf_counter() - started < 20


def test_hostile_labels_do_not_hang():
    started = time.perf_counter()
    findings(["paypal"], [("a" * 63 + ".") * 3 + "com", "x" * 63 + ".com"])
    assert time.perf_counter() - started < 5
