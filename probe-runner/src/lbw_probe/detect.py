"""Null-route detection.

Signature we flag as a LaLiga-induced block:
1. TCP `connect()` from probes in Spanish ASNs times out (not RST, not TLS fail).
2. TCP `connect()` from control probes (PT, FR) succeeds to the same target.
3. The event falls inside a LaLiga match window per `schedule.is_match_window`.
4. The (ASN, target) pair's non-match-window baseline over the last 30 days is healthy.

All four must hold. Anything less produces no incident.

Not implemented.
"""
