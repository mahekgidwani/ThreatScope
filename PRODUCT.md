# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack
Streamlit (Python) dashboard on the Windows host, reading the existing FastAPI backend over HTTP. Plotly for charts. Stack was fixed by the project brief, not chosen here.

## Users
Primary: a single security analyst triaging events from three sources (domain look-alikes, web honeypot, file analysis) on a laptop. Secondary: examiners at a college project demonstration and viva, watching a live run. Local use only; never exposed publicly.

## Product Purpose
ThreatScope collects security events from several detectors into one PostgreSQL database behind a FastAPI backend, with an experimental risk score per event. The dashboard lets the analyst see what arrived, what is severe, what repeats, and which events share indicators, and lets examiners see the system working on real data.

## Positioning
One place where three different detectors meet: events from unrelated sources are joined by the indicators they share (attacker IP, domain, file hash), and every score is labelled as an experimental prioritisation score, not a verdict.

## Operating Context
Backend and PostgreSQL run in Docker Desktop on Windows; the dashboard runs beside them on the host at 127.0.0.1:8501. Data enters through adapters (file analyser, openSquat-derived domain adapter, ModSecurity honeypot adapter). Network monitoring (Zeek) is deferred. Two demo events exist and must not be deleted.

## Capabilities and Constraints
- Dashboard talks to the API only; it never touches PostgreSQL and never duplicates risk scoring.
- API reads are open. Event ingestion and incident writes need the API key. The dashboard reads `INGEST_API_KEY` (if set) only to create and edit incidents; it never ingests events, and without the key it is read-only.
- No hardcoded or fabricated data; empty and error states must say so plainly.
- Findings are leads, not verdicts: an indicator existing does not make it malicious.
- Incident write operations did not exist in the API at the start of Phase 4 (see docs/DASHBOARD.md).

## Brand Commitments
Name: ThreatScope (folder is spelled ThreaScope; nothing is renamed). Visual direction pinned by the user: professional SOC / threat-intelligence look, dark navy and charcoal, cyan/teal accents, red for critical, orange high, amber medium, blue low, grey info, green healthy. The user's earlier reference image was not available; the written brief is the reference.

## Evidence on Hand
Real data only: two demo events and three indicators at the time of writing, no incidents. Do not fabricate more to make screens look full.

## Product Principles
1. Every number on screen comes from an API response or is an obvious empty state.
2. Severity is always readable without colour (label plus colour).
3. Say what a score is: experimental prioritisation, not probability of compromise.
4. Errors name the problem and the recovery; the dashboard never crashes or shows stale data as live.
5. Scanability over decoration: dense but calm, one accent.

## Accessibility & Inclusion
Text contrast at least 4.5:1, severity never conveyed by colour alone, keyboard-reachable controls, usable on a normal laptop width.
