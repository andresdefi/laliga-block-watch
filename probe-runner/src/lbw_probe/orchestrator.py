"""Cycle orchestration: plan dry-runs and replay recorded observations.

Two side-effect-free entry points live here:

- build_plan / plan_summary - compute and render what a live measurement
  cycle would schedule. The operator uses this to sanity-check RIPE Atlas
  credit spend before authorizing a live run.
- load_fixture / replay_fixture - take a JSON bundle of ProbeObservations,
  a match record, and baseline stats, and run the detection pipeline
  against it. This is how we regression-test the detector and how we can
  reprocess archived Atlas output without re-hitting the network.

A live_cycle() function that actually schedules measurements against
RIPE Atlas is intentionally absent from this module. It will live in its
own module when added so this file stays easy to unit-test.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from lbw_probe.detect import (
    BaselineStats,
    DetectionConfig,
    ProbeObservation,
    detect_block,
)
from lbw_probe.schedule import Match
from lbw_probe.storage import IncidentRow
from lbw_probe.targets import Target


@dataclass(frozen=True)
class Plan:
    target_count: int
    regions: tuple[str, ...]
    probes_per_region: int

    @property
    def total_probe_observations(self) -> int:
        return self.target_count * len(self.regions) * self.probes_per_region


def build_plan(
    targets: Iterable[Target],
    regions: tuple[str, ...] = ("ES", "PT", "FR"),
    probes_per_region: int = 3,
) -> Plan:
    return Plan(
        target_count=sum(1 for _ in targets),
        regions=regions,
        probes_per_region=probes_per_region,
    )


def plan_summary(plan: Plan) -> str:
    return "\n".join(
        [
            f"targets:             {plan.target_count}",
            f"regions:             {', '.join(plan.regions)}",
            f"probes per region:   {plan.probes_per_region}",
            f"total probe-obs:     {plan.total_probe_observations}",
        ]
    )


@dataclass(frozen=True)
class FixtureBundle:
    match: Match
    observations: list[ProbeObservation]
    baseline: dict[tuple[int, str], BaselineStats]


def _parse_iso(ts: str) -> datetime:
    d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def load_fixture(path: Path) -> FixtureBundle:
    raw = json.loads(path.read_text())
    m = raw["match"]
    match = Match(
        id=int(m["id"]),
        kickoff_utc=_parse_iso(m["kickoff_utc"]),
        home=str(m["home"]),
        away=str(m["away"]),
        status=str(m.get("status", "")),
    )
    observations: list[ProbeObservation] = [
        ProbeObservation(
            probe_id=int(o["probe_id"]),
            asn=(int(o["asn"]) if o.get("asn") is not None else None),
            country_code=str(o["country_code"]),
            target_ip=str(o["target_ip"]),
            target_label=str(o["target_label"]),
            outcome=o["outcome"],
            observed_at=_parse_iso(o["observed_at"]),
        )
        for o in raw["observations"]
    ]
    baseline: dict[tuple[int, str], BaselineStats] = {
        (int(b["asn"]), str(b["target_ip"])): BaselineStats(
            asn=int(b["asn"]),
            target_ip=str(b["target_ip"]),
            success_rate=float(b["success_rate"]),
            sample_size=int(b["sample_size"]),
        )
        for b in raw.get("baseline", [])
    }
    return FixtureBundle(match=match, observations=observations, baseline=baseline)


def replay_fixture(
    bundle: FixtureBundle,
    config: DetectionConfig | None = None,
) -> list[IncidentRow]:
    return detect_block(bundle.observations, bundle.match, bundle.baseline, config)
