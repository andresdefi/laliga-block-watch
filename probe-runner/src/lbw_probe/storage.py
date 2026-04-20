"""Postgres writer for probe results and detected incidents.

Schema (see migrations/ when they exist):
- `probe_results(ts, probe_id, asn, country, target_ip, target_port, outcome, rtt_ms)`
- `incidents(id, started_at, ended_at, target_ip, target_label, match_id, evidence_json)`
- `user_targets(id, submitted_at, url, contact_email, verified)`

Not implemented.
"""
