# laliga-block-watch

Public transparency tool that detects, in real time, which internet services are collaterally blocked in Spain by LaLiga's anti-piracy IP blocking orders, and produces court-admissible evidence for affected citizens.

## Why this exists

Since December 2024, a Spanish court order lets LaLiga require ISPs (and since February 2026, VPN providers) to null-route IP ranges during match windows. Roughly 3,000 IPs are blocked per weekend, with ~13,500 legitimate sites hit as collateral damage: GPS trackers for dementia patients (PAJ Portal v2), home alarm systems, Docker Hub, GitHub, Steam, X, ski resort sites, bank services, and more. There is no appeal process and no public audit of what gets blocked.

The public inciting incident: a father with dementia went missing while wearing a GPS tracker whose backend was collaterally blocked during a LaLiga match. The family could not locate him until the match ended. Similar stories are accumulating but are scattered across social media.

This project exists because:
1. Citizens need a way to check in real time whether a service they depend on is currently blocked.
2. Journalists, regulators (CNMC, Defensor del Pueblo) and courts need aggregated, time-stamped, cryptographically notarized evidence.
3. Nobody has built the citizen-facing "did LaLiga break your app today?" tool. Cloudflare Radar and daniel.es have pieces but not the whole thing.

## What it does not do

This project ships zero circumvention tooling. No VPN, no proxy, no DNS tricks. It is purely observational. This is the legal shield and the press credibility. Do not add anything that helps users bypass blocks; direct those users to existing VPN providers outside the project.

## Architecture

Three layers:

**1. Measurement**
- Primary vantage: RIPE Atlas probes across Spanish ASNs (Movistar/Telefonica, Orange, Vodafone, Digi). Scheduled TCP-connect and traceroute measurements via RIPE Atlas REST API.
- Control vantage: RIPE Atlas probes in Portugal and France to distinguish "globally down" from "blocked only in Spain".
- Volunteer browser probes (later): small JS snippet that fetches a canary list and POSTs results.
- Target list: Cloudflare published IP ranges (sampled 1 IP per /24), known affected services, user-submitted services, LaLiga match schedule pulled from their public API.

**2. Detection**
- Signature of a null-route: TCP connect timeout from Spanish ASNs, success from control vantage. Not a TLS failure, not an HTTP error.
- Baseline each (ASN, target) pair over the last 30 days of non-match windows.
- Flag as blocked when reachability drops significantly during a LaLiga match window while control stays healthy.

**3. Presentation and evidence**
- Public "is my service blocked right now?" page.
- Live incident feed, map of ongoing blocks, per-service heatmap of affected weekends.
- User submission form that lets citizens register a service they depend on.
- Complaint generator that bundles incident evidence into a signed PDF auto-filed with CNMC and Defensor del Pueblo.
- OpenTimestamps notarization of each incident bundle so the evidence is court-admissible.
- Public API and RSS feed of incidents for press.

## Stack

- Probe runner: Python 3.12, asyncio, RIPE Atlas REST API
- Storage: ClickHouse for probe time-series, Postgres for incidents and user submissions
- API: FastAPI
- Frontend: Next.js + Tailwind, MapLibre for the live block map, Recharts for heatmaps
- Hosting: outside Spain. Hetzner Helsinki or Fly.io fra region.

## Build order

- Week 1: probe runner + RIPE Atlas integration + target list seeder, logging to Postgres. Backfill the last 8 weekends to validate detection.
- Week 2: detection algorithm + LaLiga schedule correlation. Reproduce known incidents.
- Week 3: public "check my service" page + live feed.
- Week 4: user submissions + auto-complaint generator.
- Later: browser-probe SDK, OpenTimestamps notarization, press partnerships.

## Current status

- Repo initialized, public on GitHub.
- Project docs written.
- `probe-runner/src/lbw_probe/atlas.py`: RIPE Atlas async client (TCP traceroute, sslcert, find_probes, get_results) - implemented.
- `probe-runner/src/lbw_probe/targets.py`: Cloudflare /24 sampler + known-affected services resolver - implemented.
- `probe-runner/src/lbw_probe/schedule.py`: football-data.org client + `is_match_window()` pure function - implemented.
- `probe-runner/src/lbw_probe/storage.py`: psycopg3 async Storage class (probe_results, incidents, user_targets, matches) - implemented.
- `probe-runner/src/lbw_probe/detect.py`: ProbeObservation + BaselineStats + DetectionConfig, `normalize_sslcert_result()`, `compute_baseline()`, `detect_block()` pure function with four gates (spain timeout rate, control success rate, healthy baseline, match window) - implemented.
- `probe-runner/src/lbw_probe/cli.py`: typer commands `version`, `migrate`, `refresh-schedule`, `refresh-targets`, `dry-run`, `replay`, `run-cycle` - implemented.
- `probe-runner/src/lbw_probe/orchestrator.py`: `build_plan`, `plan_summary`, `load_fixture`, `replay_fixture` - side-effect-free.
- `probe-runner/src/lbw_probe/live.py`: live Atlas cycle orchestrator - `CycleConfig`, `ProbeMetaCache`, `schedule_cycle`, `wait_for_results`, `normalize_cycle`, `run_live_cycle`, `estimate_credits`. Schedules sslcert measurements, polls for results, enriches with per-probe country/ASN, emits `ProbeResultRow` + `ProbeObservation`, optionally runs `detect_block`. This is the one module that actually burns RIPE Atlas credits.
- `IncidentRow` now lives in `detect.py` (not storage.py) to break a circular import. `storage.py` imports it from `detect.py`.
- `Storage.fetch_historical_observations(since, until)` and `Storage.fetch_active_match(now, pre, post)` implemented so `run-cycle` can load baseline and current match from Postgres.
- `probe-runner/fixtures/sample_block.json`: synthetic bundle that trips the detector end-to-end. `lbw-probe replay fixtures/sample_block.json` works.
- `probe-runner/migrations/001_init.sql`: initial Postgres schema - in place.
- `probe-runner/tests/`: 34 tests passing. Pyright strict + ruff clean.
- Not yet implemented: API (FastAPI), frontend (Next.js), OpenTimestamps notarization, volunteer browser probe SDK, auto-complaint PDF generator.
- First live run: `lbw-probe migrate && lbw-probe refresh-schedule && lbw-probe run-cycle` (defaults are tiny: 2 targets x 3 regions x 1 probe = ~60 credits).

## Operational rules

- Open source from day one. Makes the project uncensorable and gives journalists their own copy.
- Do not host any production component in Spain.
- Do not incorporate any entity in Spain if a legal entity is needed later.
- Do not ship any circumvention functionality in this repo.
- Every external claim on the dashboard must be backed by a specific, timestamped, replayable measurement in the database. No guesses, no aggregated-for-style numbers. A regulator must be able to click any incident and see the raw probe data that proves it.

## Conventions

- Python: strict typing (pyright in strict mode), ruff for linting, uv for dependency management.
- Named exports where the language allows.
- Follow existing patterns before introducing new ones.
- Never commit secrets, API tokens, or probe credentials. Use `.env` locally and secret manager in production.

## Maintenance of this file

This file is the source of truth for project intent and state. Update it whenever any of the following change:
- A new architectural decision is made or reversed.
- A build-order milestone is started or completed.
- A new risk or constraint is discovered.
- Stack, hosting, or operational rules change.

Do not let this file rot. If a section here no longer matches reality, fix this file in the same commit that introduces the change.
