"""Tests for orchestrator plan + fixture replay."""

from __future__ import annotations

from pathlib import Path

from lbw_probe.orchestrator import (
    Plan,
    build_plan,
    load_fixture,
    plan_summary,
    replay_fixture,
)
from lbw_probe.targets import Target

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample_block.json"


def _tgt(ip: str) -> Target:
    return Target(
        ip=ip,
        port=443,
        label=f"cloudflare:{ip}",
        category="cloudflare_sample",
    )


def test_build_plan_math() -> None:
    targets = [_tgt("1.1.1.1"), _tgt("2.2.2.2"), _tgt("3.3.3.3")]
    plan = build_plan(targets, regions=("ES", "PT"), probes_per_region=4)
    assert plan.target_count == 3
    assert plan.regions == ("ES", "PT")
    assert plan.probes_per_region == 4
    assert plan.total_probe_observations == 3 * 2 * 4


def test_build_plan_zero_targets() -> None:
    plan = build_plan([], regions=("ES",), probes_per_region=3)
    assert plan.target_count == 0
    assert plan.total_probe_observations == 0


def test_plan_summary_has_all_fields() -> None:
    p = Plan(target_count=10, regions=("ES", "PT", "FR"), probes_per_region=3)
    text = plan_summary(p)
    assert "10" in text
    assert "ES" in text
    assert "PT" in text
    assert "FR" in text
    assert "90" in text  # 10 * 3 * 3


def test_load_fixture_roundtrip_fields() -> None:
    bundle = load_fixture(FIXTURE_PATH)
    assert bundle.match.id == 42
    assert bundle.match.home == "Real Madrid"
    assert bundle.match.away == "Barcelona"
    assert len(bundle.observations) == 5
    assert len(bundle.baseline) == 2
    assert bundle.baseline[(3352, "104.16.0.1")].success_rate == 0.99


def test_replay_fixture_detects_sample_block() -> None:
    bundle = load_fixture(FIXTURE_PATH)
    incidents = replay_fixture(bundle)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.target_ip == "104.16.0.1"
    assert inc.match_id == 42
    assert set(inc.affected_asns) == {3352, 12479}
    assert inc.evidence["spain_timeout_rate"] == 1.0
    assert inc.evidence["control_success_rate"] == 1.0
