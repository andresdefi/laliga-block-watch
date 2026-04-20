"""RIPE Atlas REST client.

Thin async wrapper around the endpoints we use:
- POST /measurements/        create a measurement
- GET  /measurements/{id}/   measurement metadata
- GET  /measurements/{id}/results/  results
- GET  /probes/              find probes

Only TCP traceroute and SSL-cert measurement types are exposed; those are the
two we rely on to detect ISP null-routes (TCP connect timeout from Spain while
a control probe outside Spain succeeds).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

BASE_URL = "https://atlas.ripe.net/api/v2"

ProbeSelector = Literal["country", "asn", "probes", "area"]


@dataclass(frozen=True)
class MeasurementRequest:
    """Minimal shape for a one-off measurement we schedule.

    `target` is an IP literal; RIPE Atlas also accepts hostnames but we always
    probe specific IPs so that detection isolates routing from DNS.
    """

    target: str
    af: Literal[4, 6] = 4
    port: int = 443
    description: str = ""


@dataclass
class AtlasClient:
    api_key: str
    base_url: str = BASE_URL
    timeout_s: float = 30.0

    def headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Key {self.api_key}",
            "Content-Type": "application/json",
        }

    @staticmethod
    def build_tcp_traceroute_payload(
        request: MeasurementRequest,
        probe_selector: ProbeSelector,
        probe_value: str,
        probe_count: int,
    ) -> dict[str, Any]:
        """Build the JSON body for POST /measurements/ (TCP traceroute).

        Pure function. Exposed so tests can assert the request shape without
        hitting the network.
        """
        return {
            "definitions": [
                {
                    "type": "traceroute",
                    "af": request.af,
                    "target": request.target,
                    "protocol": "TCP",
                    "port": request.port,
                    "description": request.description,
                    "is_oneoff": True,
                    "packets": 3,
                    "response_timeout": 4000,
                }
            ],
            "probes": [
                {
                    "type": probe_selector,
                    "value": probe_value,
                    "requested": probe_count,
                }
            ],
        }

    @staticmethod
    def build_sslcert_payload(
        request: MeasurementRequest,
        probe_selector: ProbeSelector,
        probe_value: str,
        probe_count: int,
    ) -> dict[str, Any]:
        """Build the JSON body for POST /measurements/ (SSL cert fetch).

        Fails fast on TCP null-routes: `connect()` timeout yields a measurement
        result with `err: "timeout"` and no cert chain.
        """
        return {
            "definitions": [
                {
                    "type": "sslcert",
                    "af": request.af,
                    "target": request.target,
                    "port": request.port,
                    "description": request.description,
                    "is_oneoff": True,
                }
            ],
            "probes": [
                {
                    "type": probe_selector,
                    "value": probe_value,
                    "requested": probe_count,
                }
            ],
        }

    async def create_tcp_traceroute(
        self,
        request: MeasurementRequest,
        probe_selector: ProbeSelector,
        probe_value: str,
        probe_count: int,
    ) -> list[int]:
        """Schedule a one-off TCP traceroute; return created measurement IDs."""
        payload = self.build_tcp_traceroute_payload(
            request, probe_selector, probe_value, probe_count
        )
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(
                f"{self.base_url}/measurements/",
                json=payload,
                headers=self.headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return list(data.get("measurements", []))

    async def create_sslcert(
        self,
        request: MeasurementRequest,
        probe_selector: ProbeSelector,
        probe_value: str,
        probe_count: int,
    ) -> list[int]:
        """Schedule a one-off sslcert measurement; return created measurement IDs."""
        payload = self.build_sslcert_payload(
            request, probe_selector, probe_value, probe_count
        )
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.post(
                f"{self.base_url}/measurements/",
                json=payload,
                headers=self.headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return list(data.get("measurements", []))

    async def get_measurement(self, measurement_id: int) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.get(
                f"{self.base_url}/measurements/{measurement_id}/",
                headers=self.headers(),
            )
            resp.raise_for_status()
            return dict(resp.json())

    async def get_results(self, measurement_id: int) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.get(
                f"{self.base_url}/measurements/{measurement_id}/results/",
                headers=self.headers(),
            )
            resp.raise_for_status()
            raw: list[dict[str, Any]] = resp.json()
            return raw

    async def get_probe(self, probe_id: int) -> dict[str, Any] | None:
        """Fetch a single probe's metadata. Returns None on 404."""
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.get(
                f"{self.base_url}/probes/{probe_id}/",
                headers=self.headers(),
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return dict(resp.json())

    async def find_probes(
        self,
        country_code: str,
        asn: int | None = None,
        status_id: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """Look up probes by country and optional ASN.

        status_id=1 means "Connected". We never schedule measurements on
        disconnected probes.
        """
        params: dict[str, str | int] = {
            "country_code": country_code.upper(),
            "status": status_id,
            "page_size": page_size,
        }
        if asn is not None:
            params["asn"] = asn
        async with httpx.AsyncClient(timeout=self.timeout_s) as client:
            resp = await client.get(
                f"{self.base_url}/probes/",
                params=params,
                headers=self.headers(),
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return list(data.get("results", []))
