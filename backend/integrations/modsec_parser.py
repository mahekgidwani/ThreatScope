"""ModSecurity JSON audit record -> ThreatScope `honeypot` event.

Written from the log structure observed in the honeypot project's sample log and its ModSecurity
configuration (`SecAuditLogFormat JSON`, `SecAuditLogType Serial`: one JSON object per line).
No code from that project is used. Rule families and `attack-*` tags are the OWASP Core Rule Set's
public conventions.

A record looks like (only the keys used here):
    transaction.{time, transaction_id, remote_address}   time is Apache style: 08/Jan/2020:09:29:17 +0000
    request.{request_line, headers}                       request.body may exist (log part C): NEVER used
    response.{status, headers, body}                      only the status is used
    audit_data.messages[]  strings:  '... [id "941100"] [msg "..."] [data "..."] [severity "CRITICAL"] [tag "attack-xss"]'
    audit_data.{action, producer}

What is kept: attacker IP, time, rule ids/messages/severities, an attack category, CRS tags/CVEs, the
method, path, a redacted query summary, Host / User-Agent / Content-Type, the response status.
What is never kept: request or response bodies, cookies and other headers, and the `[data "..."]`
part of a rule message (it holds the attacker's payload and anything they typed, such as passwords).

Nothing is added to `url`, `domain` or `destination_ip`: those would make the honeypot's own address
an indicator shared by every attack. The only indicator an event produces is the source IP.
"""
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

from app.schemas.event import canonical_ip
from integrations.client import stable_event_id
from integrations.textutil import clean

ADAPTER_ID = "modsecurity-json-1"
NOTE = ("ModSecurity rule matches show what the WAF saw in a request; they are not a confirmed "
        "compromise or proof of who sent it.")
MAX_MESSAGES = 200
MAX_MESSAGE_CHARS = 20_000
MAX_LISTED_RULES = 20
MAX_QUERY_CHARS = 500
MAX_QUERY_FIELDS = 50

_MONTHS = {name: number for number, name in enumerate(
    "jan feb mar apr may jun jul aug sep oct nov dec".split(), start=1)}
_CLF_TIME = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})")
_FIELD = re.compile(r'\[([a-z]{2,8}) "((?:[^"\\]|\\.){0,3000})"\]')
_RULE_ID = re.compile(r"\d{1,9}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
_CRS_VERSION = re.compile(r"OWASP_CRS/[A-Za-z0-9.\-]{1,20}")
_HTTP_VERSION = re.compile(r"HTTP/\d(?:\.\d)?", re.IGNORECASE)
_METHOD = re.compile(r"[A-Za-z]{1,20}")
_SENSITIVE_PARAM = re.compile(r"pass|pwd|secret|token|auth|key|sess|sid|cookie|cred|otp|^pin$", re.IGNORECASE)

# ModSecurity severities, most to least severe. Names and the numbers 0-7 are both accepted.
_SEVERITY_NAMES = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(_SEVERITY_NAMES)}
_SEVERITY_RANK.update({str(rank): rank for rank in range(8)})
# CRS "CRITICAL" is the top level for ordinary attack rules, so it maps to "high", not "critical".
_API_SEVERITY = {0: "critical", 1: "critical", 2: "high", 3: "medium", 4: "low"}   # 5-7 -> info
_WEIGHT = {0: 5, 1: 5, 2: 5, 3: 4, 4: 3, 5: 2}                                        # others 1

_EVALUATION_FAMILIES = {949, 959, 980}      # CRS blocking-evaluation / correlation: no attack information
_HONEYTRAP_IDS = range(9_500_000, 10_000_000)

_TAG_CATEGORY = {
    "attack-xss": "xss", "attack-sqli": "sqli", "attack-lfi": "lfi", "attack-rfi": "rfi", "attack-rce": "rce",
    "attack-injection-php": "php_injection", "attack-injection-generic": "generic_injection",
    "attack-reputation-scanner": "scanner", "attack-reputation-crawler": "scanner",
    "attack-reputation-scripting": "scanner", "attack-protocol": "protocol", "attack-fixation": "session_fixation",
    "attack-disclosure": "info_leak", "attack-dos": "dos", "attack-generic": "generic_attack",
}
_FAMILY_CATEGORY = {913: "scanner", 920: "protocol", 921: "protocol", 930: "lfi", 931: "rfi", 932: "rce",
                    933: "php_injection", 934: "generic_attack", 941: "xss", 942: "sqli",
                    943: "session_fixation", 944: "rce"}
_PRIORITY = ["rce", "sqli", "xss", "lfi", "rfi", "php_injection", "session_fixation", "generic_injection",
             "generic_attack", "info_leak", "dos", "scanner", "unclassified", "protocol"]
_SECONDARY = {"protocol", "scanner", "unclassified"}      # only decide the category when nothing else fired
_EVENT_TYPE = {"scanner": "scanner_probe", "protocol": "protocol_anomaly", "unclassified": "waf_alert"}
_LABEL = {"xss": "XSS attempt", "sqli": "SQL injection attempt", "lfi": "local file inclusion / path traversal",
          "rfi": "remote file inclusion", "rce": "remote command execution", "php_injection": "PHP injection",
          "scanner": "scanner or crawler probe", "protocol": "protocol violation",
          "session_fixation": "session fixation", "generic_injection": "generic injection",
          "generic_attack": "generic web attack", "info_leak": "information disclosure", "dos": "denial of service",
          "unclassified": "web attack"}


class RecordSkipped(Exception):
    """The record does not become an event. `reason`: no_rule_hits (normal, not an error),
    invalid_ip, invalid_time or malformed."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.benign = reason == "no_rule_hits"


def parse_time(value) -> datetime:
    """Apache-style (08/Jan/2020:09:29:17 +0000) or ISO-8601 with an offset -> aware UTC.
    Raises ValueError for anything else. Never guesses a missing time zone."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("not a timestamp")
    text = value.strip()
    match = _CLF_TIME.fullmatch(text)
    try:
        if match:
            day, month, year, hour, minute, second, sign, off_h, off_m = match.groups()
            if month.lower() not in _MONTHS:
                raise ValueError("unknown month")
            offset = timedelta(hours=int(off_h), minutes=int(off_m)) * (-1 if sign == "-" else 1)
            parsed = datetime(int(year), _MONTHS[month.lower()], int(day), int(hour), int(minute), int(second),
                              tzinfo=timezone(offset))
        else:
            parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            raise ValueError("no time zone")
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        raise ValueError("outside the supported range") from None


# ---- rule messages ---------------------------------------------------------------------------

def _severity_rank(raw: str | None) -> int | None:
    return None if raw is None else _SEVERITY_RANK.get(raw.strip().upper())


def _parse_message(text: str) -> dict | None:
    """The fields of one rule message, or None if it has no usable rule id. The first occurrence of
    each key wins, and `[data "..."]` is consumed as one field and then discarded."""
    fields, tags = {}, []
    for key, value in _FIELD.findall(text[:MAX_MESSAGE_CHARS]):
        if key == "tag":
            tags.append(value)
        else:
            fields.setdefault(key, value)
    rule_id = fields.get("id", "")
    if not _RULE_ID.fullmatch(rule_id):
        return None
    rank = _severity_rank(fields.get("severity"))
    return {"id": int(rule_id), "msg": clean(fields.get("msg", ""), 120), "rank": rank,
            "tags": [t for t in tags if len(t) <= 80 and re.fullmatch(r"[A-Za-z0-9_./\-]+", t)]}


def _rule_category(rule: dict) -> str:
    for tag in rule["tags"]:
        if tag in _TAG_CATEGORY:
            return _TAG_CATEGORY[tag]
    return _FAMILY_CATEGORY.get(rule["id"] // 1000, "unclassified")


def _collect_rules(audit_data) -> list[dict]:
    if audit_data is None:
        return []
    if not isinstance(audit_data, dict):
        raise RecordSkipped("malformed", "audit_data is not an object")
    messages = audit_data.get("messages")
    if messages is None:
        return []
    if not isinstance(messages, list):
        raise RecordSkipped("malformed", "audit_data.messages is not a list")
    rules, seen = [], set()
    for text in messages[:MAX_MESSAGES]:
        rule = _parse_message(text) if isinstance(text, str) else None
        if rule is None or rule["id"] // 1000 in _EVALUATION_FAMILIES or rule["id"] in seen:
            continue
        seen.add(rule["id"])
        rules.append(rule)
    return rules


def _choose_category(rules: list[dict]) -> tuple[str, dict]:
    """The category with the most severity-weighted rule hits; protocol/scanner/unclassified only win
    when nothing else fired. Ties go to the fixed `_PRIORITY` order. Returns (winner, all scores)."""
    scores: dict[str, int] = {}
    for rule in rules:
        category = _rule_category(rule)
        scores[category] = scores.get(category, 0) + _WEIGHT.get(rule["rank"], 1)
    primary = {c: s for c, s in scores.items() if c not in _SECONDARY} or scores
    winner = min(primary, key=lambda c: (-primary[c], _PRIORITY.index(c)))
    return winner, dict(sorted(scores.items(), key=lambda item: (-item[1], _PRIORITY.index(item[0]))))


# ---- request summary -------------------------------------------------------------------------

def _query_summary(query: str) -> str | None:
    query = query.split("#", 1)[0]
    if not query:
        return None
    try:
        pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=MAX_QUERY_FIELDS)
    except ValueError:
        return f"(more than {MAX_QUERY_FIELDS} parameters)"
    parts = []
    for name, value in pairs:
        shown = "[redacted]" if _SENSITIVE_PARAM.search(name) else clean(value, 100)
        parts.append(f"{clean(name, 50)}={shown}")
    return clean("&".join(parts), MAX_QUERY_CHARS) or None


def _header(headers, wanted: str, limit: int) -> str | None:
    if not isinstance(headers, dict):
        return None
    for name, value in headers.items():
        if isinstance(name, str) and name.lower() == wanted and isinstance(value, str):
            return clean(value, limit) or None
    return None


def _request_summary(request, status) -> dict:
    summary: dict = {}
    request = request if isinstance(request, dict) else {}
    line = request.get("request_line")
    if isinstance(line, str):
        tokens = line[:2000].strip().split(" ")
        if len(tokens) >= 2 and _METHOD.fullmatch(tokens[0]):
            has_version = len(tokens) >= 3 and _HTTP_VERSION.fullmatch(tokens[-1])
            target = " ".join(tokens[1:-1] if has_version else tokens[1:])
            path, _, query = target.partition("?")
            summary["method"] = tokens[0].upper()
            summary["path"] = clean(path, 200)
            if has_version:
                summary["protocol"] = tokens[-1].upper()
            query_text = _query_summary(query)
            if query_text:
                summary["query"] = query_text
        else:
            summary["unparsed_request_line"] = clean(line[:200], 100)
    headers = request.get("headers")
    for key, header, limit in (("host", "host", 100), ("user_agent", "user-agent", 200),
                               ("content_type", "content-type", 100)):
        value = _header(headers, header, limit)
        if value:
            summary[key] = value
    return summary


# ---- the event ---------------------------------------------------------------------------------

def _external_id(transaction: dict, request) -> str:
    tid = transaction.get("transaction_id")
    if isinstance(tid, str) and tid:
        return stable_event_id("modsec", tid)
    line = request.get("request_line") if isinstance(request, dict) else None
    return stable_event_id("modsec", transaction.get("time"), transaction.get("remote_address"),
                           line[:2000] if isinstance(line, str) else "")


def build_event(record) -> dict:
    """The dict to send with ThreatScopeClient.submit_event. Raises RecordSkipped when the record is
    not an attack event or cannot be trusted. The record is not modified."""
    if not isinstance(record, dict):
        raise RecordSkipped("malformed", "record is not a JSON object")
    transaction = record.get("transaction")
    if not isinstance(transaction, dict):
        raise RecordSkipped("malformed", "record has no transaction object")

    rules = _collect_rules(record.get("audit_data"))
    if not rules:
        raise RecordSkipped("no_rule_hits", "no attack rules matched")
    try:
        source_ip = canonical_ip(transaction["remote_address"]) if isinstance(
            transaction.get("remote_address"), str) else None
        if source_ip is None:
            raise ValueError
    except (ValueError, KeyError):
        raise RecordSkipped("invalid_ip", "remote_address is missing or not an IP address") from None
    try:
        occurred_at = parse_time(transaction.get("time"))
    except ValueError:
        raise RecordSkipped("invalid_time", "transaction time is missing or not a valid timestamp") from None

    category, scores = _choose_category(rules)
    ranks = [r["rank"] for r in rules if r["rank"] is not None]
    top = min(ranks) if ranks else None
    severity = "info" if top is None else _API_SEVERITY.get(top, "info")
    audit = record["audit_data"]
    action = audit.get("action")
    blocked = action.get("intercepted") if isinstance(action, dict) and isinstance(
        action.get("intercepted"), bool) else None
    response = record.get("response")
    status = response.get("status") if isinstance(response, dict) else None
    status = status if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599 else None
    producer = audit.get("producer")
    crs = next((m.group(0) for p in producer if isinstance(p, str) and (m := _CRS_VERSION.search(p))), None
               ) if isinstance(producer, list) else None
    tags = [tag for rule in rules for tag in rule["tags"]]

    description = (f"ModSecurity reported {len(rules)} rule hit(s) for a possible {_LABEL[category]} "
                   f"(highest severity {_SEVERITY_NAMES[top] if top is not None else 'unknown'}"
                   f"{', request blocked' if blocked else ''})")
    return {
        "external_event_id": _external_id(transaction, record.get("request")),
        "source": "honeypot",
        "event_type": _EVENT_TYPE.get(category, f"{category}_attempt"),
        "occurred_at": occurred_at,
        "source_ip": source_ip,
        "severity": severity,
        "description": description,
        "metadata": {
            "adapter": ADAPTER_ID,
            "attack_category": category,
            "attack_categories": scores,
            "rule_count": len(rules),
            "rules": [{"id": r["id"], "msg": r["msg"],
                       "severity": _SEVERITY_NAMES[r["rank"]] if r["rank"] is not None else None}
                      for r in rules[:MAX_LISTED_RULES]],
            "highest_severity": _SEVERITY_NAMES[top] if top is not None else "UNKNOWN",
            "cves": list(dict.fromkeys(m.group(0) for t in tags if (m := _CVE.fullmatch(t)))),
            "honeytrap_rule_ids": [r["id"] for r in rules if r["id"] in _HONEYTRAP_IDS],
            "blocked": blocked,
            "response_status": status,
            "crs_version": crs,
            "transaction_id": clean(transaction["transaction_id"], 100) if isinstance(
                transaction.get("transaction_id"), str) else None,
            "request": _request_summary(record.get("request"), status),
            "note": NOTE,
        },
    }
