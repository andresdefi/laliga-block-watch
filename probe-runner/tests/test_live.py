"""Pure-function tests for live.py helpers.

The live cycle itself requires a real RIPE Atlas account and a live network,
so it's not covered by automated tests here. Only the deterministic helpers
that the CLI relies on (credit estimation) are tested.
"""

from __future__ import annotations

from lbw_probe.live import CycleConfig, estimate_credits


def test_estimate_credits_respects_max_targets_cap() -> None:
    cfg = CycleConfig(
        regions=("ES", "PT", "FR"), probes_per_region=1, max_targets=2
    )
    # Even if there are many targets available, only max_targets are probed.
    assert estimate_credits(cfg, target_count=1000) == 2 * 3 * 1 * 10
    assert estimate_credits(cfg, target_count=1) == 1 * 3 * 1 * 10


def test_estimate_credits_zero_targets() -> None:
    cfg = CycleConfig(max_targets=5)
    assert estimate_credits(cfg, target_count=0) == 0


def test_estimate_credits_scales_with_probes() -> None:
    cfg = CycleConfig(regions=("ES",), probes_per_region=3, max_targets=10)
    # 10 targets * 1 region * 3 probes * 10 credits/probe
    assert estimate_credits(cfg, target_count=10) == 300
