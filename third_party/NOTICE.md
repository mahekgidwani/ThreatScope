# Third-party notices and attribution

ThreatScope is licensed under the **GNU General Public License v3.0** (see `LICENSE`).
This is an academic project. Reference projects were studied. As of Phase 3 Task 3, code adapted from
openSquat is included in `backend/integrations/opensquat_detector.py` (see the table and modifications log).
Because that adapted code is GPL-3.0, **GPL-3.0 applies to ThreatScope as a whole**, not only to that file.

| Project | Licence | How ThreatScope uses it | Status |
|---|---|---|---|
| openSquat (Andre Tenreiro) https://github.com/atenreiro/opensquat | GPL-3.0 | Adapted (v2.3.0): `levenshtein` (unchanged), `check_homograph`, `homograph_to_latin` and the decision order of `SquattingDetector._process_levenshtein`, in `backend/integrations/opensquat_detector.py`, which keeps openSquat's copyright notice and a list of changes in its header. **No API keys or credentials are copied** (the reference folder contains `api_key.txt` and `vt_key.txt`; they were never read or copied). The openSquat domain feed is **not** bundled: its header says it is free for personal and research use only. | Used in Phase 3 Task 3. |
| OWASP Honeypot-Project https://github.com/owasp/honeypot-project | Not verified locally (no LICENSE file found in the downloaded copy) | **Log format only.** `backend/integrations/modsec_parser.py` reads the ModSecurity JSON audit log that its honeypot writes (`SecAuditLogFormat JSON`, one object per line). The parser and adapter are written independently from the observed field layout; **no source code, configuration or sample text from that project is copied or redistributed**, and it was not modified or started. ELK and MISP are not used. | Used in Phase 3 Task 4. Licence must still be confirmed upstream before any reuse of its code. OWASP Core Rule Set tag and rule-family conventions (`attack-xss`, rule files 941/942, ...) are public CRS conventions. |
| OWASP Core Rule Set (CRS) | Apache-2.0 | **Conventions only.** Rule-id families (941 XSS, 942 SQL injection, ...) and tag names (`attack-xss`, ...) are used to classify ModSecurity alerts. No rules, configuration or code are copied. ModSecurity itself is a separate project: ThreatScope only reads the format of its JSON audit log. | Used in Phase 3 Task 4. |
| Zeek https://zeek.org | BSD-style (UC Regents / LBNL / ICSI) | Evaluated only; **not installed, not used**. See `docs/NETWORK_DECISION.md`. | No code copied. |
| FAME (CERT Societe Generale) https://github.com/certsocietegenerale/fame | GPL-3.0 | Design reference only (file analysis workflow). | No code copied. ThreatScope builds its own lightweight static analyser. |
| OWASP Python Honeypot | Unknown | Not available locally; not used. | Architecture keeps honeypot adapters modular so it can be added later. |

## Runtime dependencies added for the openSquat adapter

| Package | Licence | Why |
|---|---|---|
| confusable_homoglyphs 3.3.x | MIT | Unicode "confusables" data; openSquat's own homograph check (`is_dangerous`). Pure Python, no further dependencies. |
| homoglyphs 2.0.x | MIT | Converts look-alike characters to Latin; openSquat's own `homograph_to_latin`. Pure Python, no further dependencies. |

Both are the same libraries openSquat itself requires. MIT is compatible with GPL-3.0.

## Runtime dependencies added for the dashboard (Phase 4, installed on the host)

| Package | Licence | Why |
|---|---|---|
| Streamlit | Apache-2.0 | The dashboard web UI (`dashboard/`). Apache-2.0 is compatible with GPL-3.0. |
| Plotly | MIT | Charts and the relationship graph. |
| httpx | BSD-3-Clause | The dashboard's HTTP client. The adapters use it too (moved to runtime in Phase 3). |

## Modifications log

openSquat 2.3.0 -> `backend/integrations/opensquat_detector.py` (Phase 3, Task 3):
1. Detection returns structured `Finding` objects instead of printing coloured text; outcomes are unchanged (similarity, homograph, keyword contained).
2. Punycode (`xn--`) names are decoded to Unicode before the homograph check. The original checks the label as written, so it reports "not a homograph" for every IDN stored as punycode (the openSquat feed stores them that way).
3. `homograph_to_latin` is lower-cased and deterministic (candidates sorted). The original joins a set, whose order changes between runs, and keeps upper case.
4. Homoglyph tables are loaded once instead of per call.
5. Input is validated and normalised with ThreatScope's own domain rules; keywords shorter than 3 characters are refused; an optional trusted-domain list skips a brand's own domains.
6. Not used: feed download, DNS/port checks, certificate transparency, VirusTotal, paid API, doppelganger mode.
