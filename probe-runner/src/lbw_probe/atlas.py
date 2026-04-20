"""RIPE Atlas REST client.

Wraps the measurement creation, status polling, and result fetching endpoints.
Only exposes the measurement types we need: TCP connect (type=tcp), traceroute,
and DNS. Uses probe selection by country (ES, PT, FR) and ASN tags.

Not implemented.
"""
