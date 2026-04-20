"""Pure-function tests for targets.sample_ip_per_24."""

from __future__ import annotations

from lbw_probe.targets import (
    Target,
    sample_ip_per_24,
    targets_from_cidrs,
)


def test_sample_ip_per_24_exact_24() -> None:
    out = sample_ip_per_24("104.16.0.0/24")
    assert out == ["104.16.0.1"]


def test_sample_ip_per_24_smaller_than_24_returns_single() -> None:
    out = sample_ip_per_24("104.16.0.0/28")
    assert out == ["104.16.0.1"]


def test_sample_ip_per_24_larger_prefix_yields_multiple() -> None:
    out = sample_ip_per_24("104.16.0.0/22")
    assert out == [
        "104.16.0.1",
        "104.16.1.1",
        "104.16.2.1",
        "104.16.3.1",
    ]


def test_sample_ip_per_24_ipv6_ignored() -> None:
    assert sample_ip_per_24("2606:4700::/32") == []


def test_targets_from_cidrs_labels_and_category() -> None:
    out = targets_from_cidrs(["198.51.100.0/23"])
    assert len(out) == 2
    assert all(isinstance(t, Target) for t in out)
    assert all(t.category == "cloudflare_sample" for t in out)
    assert all(t.port == 443 for t in out)
    assert out[0].ip == "198.51.100.1"
    assert out[1].ip == "198.51.101.1"
    assert out[0].label == "cloudflare:198.51.100.0/23:198.51.100.1"
