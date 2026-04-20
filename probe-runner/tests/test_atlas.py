"""Payload-shape tests for atlas.AtlasClient.

We do not hit the RIPE Atlas network. We only assert that the JSON bodies we
build for POST /measurements/ match what the API expects, because getting that
shape wrong is the most common source of 400s from this endpoint.
"""

from __future__ import annotations

from lbw_probe.atlas import AtlasClient, MeasurementRequest


def test_tcp_traceroute_payload_shape() -> None:
    req = MeasurementRequest(target="1.1.1.1", port=443, description="cf-sample")
    payload = AtlasClient.build_tcp_traceroute_payload(
        req,
        probe_selector="country",
        probe_value="ES",
        probe_count=5,
    )
    assert payload["definitions"][0]["type"] == "traceroute"
    assert payload["definitions"][0]["protocol"] == "TCP"
    assert payload["definitions"][0]["af"] == 4
    assert payload["definitions"][0]["target"] == "1.1.1.1"
    assert payload["definitions"][0]["port"] == 443
    assert payload["definitions"][0]["is_oneoff"] is True
    assert payload["probes"][0] == {
        "type": "country",
        "value": "ES",
        "requested": 5,
    }


def test_sslcert_payload_shape() -> None:
    req = MeasurementRequest(target="104.16.0.1", port=443, description="paj")
    payload = AtlasClient.build_sslcert_payload(
        req,
        probe_selector="asn",
        probe_value="3352",
        probe_count=3,
    )
    assert payload["definitions"][0]["type"] == "sslcert"
    assert payload["definitions"][0]["target"] == "104.16.0.1"
    assert payload["definitions"][0]["is_oneoff"] is True
    assert payload["probes"][0] == {
        "type": "asn",
        "value": "3352",
        "requested": 3,
    }


def test_headers_includes_key_auth() -> None:
    client = AtlasClient(api_key="fake-key")
    h = client.headers()
    assert h["Authorization"] == "Key fake-key"
    assert h["Content-Type"] == "application/json"
