"""Target list management.

A Target is a (ip, port, label, category) tuple the probe runner cycles through
on every measurement round. The initial list is seeded from three sources:

1. Cloudflare's published IPv4 ranges (sampled one IP per /24).
2. A hardcoded seed of known-affected consumer services.
3. User-submitted URLs from the `user_targets` Postgres table (loaded separately).

The Cloudflare sample is what gives us broad coverage of the block: LaLiga's
orders target whole Cloudflare ranges, so a representative IP from each /24
tells us which specific /24s are null-routed this weekend.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Literal

import httpx

CLOUDFLARE_V4_LIST_URL = "https://www.cloudflare.com/ips-v4"

Category = Literal["cloudflare_sample", "known_service", "user_submitted"]


@dataclass(frozen=True)
class Target:
    ip: str
    port: int
    label: str
    category: Category


KNOWN_AFFECTED_SERVICES: tuple[tuple[str, str], ...] = (
    ("portal.paj-gps.de", "paj-portal-v2"),
    ("glovoapp.com", "glovo"),
    ("hub.docker.com", "docker-hub"),
    ("registry-1.docker.io", "docker-registry"),
    ("x.com", "x-twitter"),
    ("www.twitch.tv", "twitch"),
    ("steamcommunity.com", "steam-community"),
    ("www.linkedin.com", "linkedin"),
    ("www.securitasdirect.es", "securitas-direct"),
)


def sample_ip_per_24(cidr: str) -> list[str]:
    """Return one representative IP per /24 inside the given CIDR block.

    For prefixes /24 or smaller, returns a single IP (host index 1).
    Larger prefixes (e.g. /20) yield multiple /24 samples.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        return []

    if net.prefixlen >= 24:
        hosts = list(net.hosts())
        return [str(hosts[0])] if hosts else []

    subnets_24 = net.subnets(new_prefix=24)
    out: list[str] = []
    for sub in subnets_24:
        hosts = list(sub.hosts())
        if hosts:
            out.append(str(hosts[0]))
    return out


def targets_from_cidrs(cidrs: Iterable[str], port: int = 443) -> list[Target]:
    out: list[Target] = []
    for cidr in cidrs:
        for ip in sample_ip_per_24(cidr):
            out.append(
                Target(
                    ip=ip,
                    port=port,
                    label=f"cloudflare:{cidr}:{ip}",
                    category="cloudflare_sample",
                )
            )
    return out


async def fetch_cloudflare_v4_ranges(timeout_s: float = 10.0) -> list[str]:
    """Fetch Cloudflare's public IPv4 CIDR list.

    Format is plaintext, one CIDR per line. We keep network calls in this
    module rather than in the caller so tests can monkey-patch this one
    function.
    """
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.get(CLOUDFLARE_V4_LIST_URL)
        resp.raise_for_status()
        return [
            line.strip()
            for line in resp.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]


async def resolve_known_services(
    services: Iterable[tuple[str, str]] = KNOWN_AFFECTED_SERVICES,
    port: int = 443,
) -> list[Target]:
    """Resolve hostnames of known-affected services to A records.

    One target per resolved IP. A single hostname may produce several targets
    when the service uses a CDN with multiple edge IPs.
    """
    import asyncio
    import socket

    loop = asyncio.get_running_loop()
    out: list[Target] = []

    for hostname, label in services:
        try:
            infos = await loop.run_in_executor(
                None, socket.getaddrinfo, hostname, port, socket.AF_INET
            )
        except socket.gaierror:
            continue
        seen: set[str] = set()
        for info in infos:
            sockaddr = info[4]
            ip = str(sockaddr[0])
            if ip in seen:
                continue
            seen.add(ip)
            out.append(
                Target(
                    ip=ip,
                    port=port,
                    label=f"service:{label}:{hostname}",
                    category="known_service",
                )
            )
    return out
