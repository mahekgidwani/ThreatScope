"""Synthetic ModSecurity JSON audit records, shaped like the structure observed in the honeypot
project's sample log (own fixtures; no sample text is copied)."""
import json

CANARY = "CANARY-SECRET-9f3a"       # must never appear in an event, an output line or a state file


def rule(rule_id, msg, severity="CRITICAL", tags=(), file="REQUEST-941-APPLICATION-ATTACK-XSS.conf",
         data=f'Matched Data: found within ARGS:q: {CANARY}'):
    """One entry of audit_data.messages, in ModSecurity's '[key "value"]' text layout."""
    parts = [f'Warning. Pattern match at ARGS:q. [file "/etc/modsecurity.d/owasp-crs/rules/{file}"] [line "59"]',
             f'[id "{rule_id}"]', f'[msg "{msg}"]', f'[data "{data}"]']
    if severity is not None:
        parts.append(f'[severity "{severity}"]')
    parts.append('[ver "OWASP_CRS/3.2.0"]')
    parts += [f'[tag "{tag}"]' for tag in tags]
    return " ".join(parts)


XSS = [rule(941100, "XSS Attack Detected via libinjection", tags=["attack-xss", "OWASP_CRS"]),
       rule(941110, "XSS Filter - Category 1: Script Tag Vector", tags=["attack-xss"])]
SQLI = [rule(942100, "SQL Injection Attack Detected via libinjection", "CRITICAL", ["attack-sqli"],
             "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")]
EVALUATION = [rule(949110, "Inbound Anomaly Score Exceeded (Total Score: 10)", "CRITICAL", ["attack-generic"],
                   "REQUEST-949-BLOCKING-EVALUATION.conf", "")]


def record(messages=None, remote="203.0.113.7", time="08/Jan/2020:09:29:17 +0000", transaction_id="Xh-unique-001",
           request_line="GET /search?q=<script>alert(1)</script> HTTP/1.1", status=403, headers=None, **extra):
    base = {
        "transaction": {"time": time, "transaction_id": transaction_id, "remote_address": remote,
                        "remote_port": 56224, "local_address": "172.17.0.2", "local_port": 80},
        "request": {"request_line": request_line,
                    "headers": headers if headers is not None else
                    {"Host": "shop.example", "User-Agent": "curl/7.67.0", "Accept": "*/*"}},
        "response": {"protocol": "HTTP/1.1", "status": status,
                     "headers": {"Set-Cookie": f"session={CANARY}", "Content-Type": "text/html"},
                     "body": f"<html>{CANARY}</html>"},
        "audit_data": {"messages": list(XSS + EVALUATION if messages is None else messages),
                       "error_messages": [], "action": {"intercepted": True, "phase": 2},
                       "producer": ["ModSecurity for Apache/2.9.3", "OWASP_CRS/3.2.0"],
                       "server": "Apache", "engine_mode": "ENABLED"},
    }
    base.update(extra)
    return base


def line(rec) -> str:
    return json.dumps(rec)
