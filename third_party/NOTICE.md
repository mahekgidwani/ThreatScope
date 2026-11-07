# Third-party notices and attribution

ThreatScope is licensed under the **GNU General Public License v3.0** (see `LICENSE`).
This is an academic project. Reference projects were studied; no code has been copied
into this repository as of Phase 2.

| Project | Licence | How ThreatScope uses it | Status |
|---|---|---|---|
| openSquat (Andre Tenreiro) https://github.com/atenreiro/opensquat | GPL-3.0 | Domain-squatting detection logic will be adapted in Phase 3 (Levenshtein / homograph checks). | Not yet used. When adapted, copyright headers are kept and every modification is listed here. **No API keys or credentials are copied** (the reference folder contains `api_key.txt` and `vt_key.txt`; they are never read or copied). |
| OWASP Honeypot-Project https://github.com/owasp/honeypot-project | Not verified locally (no LICENSE file found in the downloaded copy) | ModSecurity web-honeypot container and its v1.1 JSON event schema are the planned honeypot source in Phase 3. ELK and MISP are not used. | Licence must be confirmed upstream before any reuse. OWASP will be credited. |
| FAME (CERT Societe Generale) https://github.com/certsocietegenerale/fame | GPL-3.0 | Design reference only (file analysis workflow). | No code copied. ThreatScope builds its own lightweight static analyser. |
| OWASP Python Honeypot | Unknown | Not available locally; not used. | Architecture keeps honeypot adapters modular so it can be added later. |

## Modifications log

None yet.
