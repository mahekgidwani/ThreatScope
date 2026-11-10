"""The demo files in backend/demo: a fresh clone must produce valid events with a shared indicator."""
import ipaddress
import json
import re
from pathlib import Path

from app.schemas.event import EventIn
from app.services.indicator_extractor import extract_indicators
from integrations.file_analyser import analyse_file, build_event as file_event
from integrations.modsec_parser import build_event as modsec_event
from integrations.opensquat_adapter import iter_lines
from integrations.opensquat_detector import build_event as squat_event, clean_keyword, find_squatting, prepare_domain

DEMO = Path(__file__).resolve().parents[2] / "demo"
DOC_RANGES = [ipaddress.ip_network(n) for n in ("203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24")]


def demo_events():
    keywords = [k for k in map(clean_keyword, iter_lines(DEMO / "brands.txt")) if k]
    domains = [d for d in map(prepare_domain, iter_lines(DEMO / "domains.txt")) if d]
    events = [squat_event(f) for f in find_squatting(keywords, domains)]
    events += [modsec_event(json.loads(text)) for text in (DEMO / "modsec_audit.log").read_text("utf-8").splitlines() if text]
    events.append(file_event(analyse_file(DEMO / "note.txt")))
    return events


def test_demo_files_build_valid_events_with_a_shared_indicator():
    events = [EventIn(**e) for e in demo_events()]
    assert len(events) >= 3
    counts = {}
    for event in events:
        for indicator in extract_indicators(event):
            counts[indicator] = counts.get(indicator, 0) + 1
    assert max(counts.values()) >= 2


def test_demo_files_hold_only_documentation_ips_and_no_key_like_strings():
    for path in DEMO.glob("*"):
        if path.suffix == ".ps1":
            continue
        text = path.read_text("utf-8")
        assert not re.search(r"[0-9a-fA-F]{24,}", text), path.name
        for ip in re.findall(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])", text):
            assert any(ipaddress.ip_address(ip) in net for net in DOC_RANGES), (path.name, ip)


def test_demo_files_exist_under_names_git_does_not_ignore():
    # .gitignore hides *.log (negated for backend/demo) and *key*.txt, so a keywords.txt would vanish
    # from a clone. git is not in the container image; tracking is checked with `git ls-files backend/demo`.
    names = {"brands.txt", "domains.txt", "modsec_audit.log", "note.txt", "load-demo.ps1"}
    assert names <= {p.name for p in DEMO.iterdir()}
    assert not [n for n in names if "key" in n.lower() and n.endswith(".txt")]
