"""Live RIPE Atlas measurement cycle.

This is the one module that actually burns RIPE Atlas credits. It:

1. Schedules one sslcert measurement per (target, region) against N probes.
2. Polls Atlas until results appear for every scheduled measurement, with
   a bounded timeout (one-off sslcerts usually resolve in ~60-120s).
3. Fetches probe metadata (country_code, asn_v4) on demand and caches it
   per cycle - one /probes/{id}/ call per unique probe, then reuse.
4. Normalizes raw Atlas payloads into (ProbeResultRow, ProbeObservation)
   pairs: the row gets persisted verbatim; the observation feeds detection.
5. Optionally runs `detect_block` when a live match and a usable baseline
   are supplied.

Keep this module side-effect free with respect to storage: the caller
persists results. That way it stays unit-testable with mock clients and
the CLI can swap persistence for a dry-run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

import httpx

from lbw_probe.atlas import AtlasClient, MeasurementRequest
from lbw_probe.detect import (
    BaselineStats,
    DetectionConfig,
    IncidentRow,
    ProbeObservation,
    detect_block,
    normalize_sslcert_result,
)
from lbw_probe.schedule import Match
from lbw_probe.storage import ProbeResultRow
from lbw_probe.targets import Target

SSLCERT_CREDITS_PER_PROBE = 10


@dataclass(frozen=True)
class CycleConfig:
    regions: tuple[str, ...] = ("ES", "PT", "FR")
    probes_per_region: int = 1
    max_targets: int = 2
    result_poll_interval_s: float = 10.0
    result_timeout_s: float = 300.0


@dataclass(frozen=True)
class ProbeMeta:
    id: int
    country_code: str
    asn: int | None


class ProbeMetaCache:
    """Lazy per-cycle cache of probe metadata.

    Atlas returns raw result records with only `prb_id`; country and ASN live
    on the probe object. We fetch once and cache for the remainder of the
    cycle so a single probe contributing multiple observations hits the API
    only once.
    """

    def __init__(self, client: AtlasClient) -> None:
        self.client = client
        self._cache: dict[int, ProbeMeta] = {}

    async def get(self, probe_id: int) -> ProbeMeta | None:
        cached = self._cache.get(probe_id)
        if cached is not None:
            return cached
        raw = await self.client.get_probe(probe_id)
        if raw is None:
            return None
        meta = ProbeMeta(
            id=probe_id,
            country_code=str(raw.get("country_code") or "").upper(),
            asn=raw.get("asn_v4"),
        )
        self._cache[probe_id] = meta
        return meta


@dataclass(frozen=True)
class ScheduledMeasurement:
    measurement_id: int
    target: Target
    region: str


@dataclass
class CycleResult:
    scheduled: list[ScheduledMeasurement]
    rows: list[ProbeResultRow]
    observations: list[ProbeObservation]
    incidents: list[IncidentRow]


def estimate_credits(cfg: CycleConfig, target_count: int) -> int:
    """Ballpark credit cost of a cycle. sslcert costs ~10 credits per probe."""
    actual = min(cfg.max_targets, target_count)
    return actual * len(cfg.regions) * cfg.probes_per_region * SSLCERT_CREDITS_PER_PROBE


async def schedule_cycle(
    client: AtlasClient,
    targets: list[Target],
    cfg: CycleConfig,
    description_prefix: str = "lbw",
) -> list[ScheduledMeasurement]:
    """Create one sslcert measurement per (target, region). Parallelized."""
    sliced = targets[: cfg.max_targets]

    async def _one(target: Target, region: str) -> ScheduledMeasurement:
        req = MeasurementRequest(
            target=target.ip,
            port=target.port,
            description=f"{description_prefix}:{target.label}:{region}",
        )
        ids = await client.create_sslcert(req, "country", region, cfg.probes_per_region)
        if not ids:
            raise RuntimeError(f"atlas returned no measurement id for {target.ip}/{region}")
        return ScheduledMeasurement(measurement_id=ids[0], target=target, region=region)

    coros = [_one(t, r) for t in sliced for r in cfg.regions]
    return list(await asyncio.gather(*coros))


async def wait_for_results(
    client: AtlasClient,
    scheduled: list[ScheduledMeasurement],
    cfg: CycleConfig,
) -> dict[int, list[dict[str, Any]]]:
    """Poll every measurement's results endpoint until all return or timeout."""
    out: dict[int, list[dict[str, Any]]] = {s.measurement_id: [] for s in scheduled}
    pending = {s.measurement_id for s in scheduled}
    loop = asyncio.get_event_loop()
    deadline = loop.time() + cfg.result_timeout_s

    while pending and loop.time() < deadline:
        for mid in list(pending):
            results = await client.get_results(mid)
            if results:
                out[mid] = results
                pending.discard(mid)
        if pending:
            await asyncio.sleep(cfg.result_poll_interval_s)

    return out


async def normalize_cycle(
    raw_by_mid: Mapping[int, list[dict[str, Any]]],
    scheduled: list[ScheduledMeasurement],
    meta_cache: ProbeMetaCache,
) -> tuple[list[ProbeResultRow], list[ProbeObservation]]:
    """Convert raw Atlas sslcert results into storage rows and detection obs.

    One input result → one row + one observation (unless probe metadata
    cannot be fetched or the record is malformed, in which case we drop it).
    Raw payload is preserved on the row for evidence replay.
    """
    ctx: dict[int, ScheduledMeasurement] = {s.measurement_id: s for s in scheduled}

    rows: list[ProbeResultRow] = []
    observations: list[ProbeObservation] = []

    for mid, raw_list in raw_by_mid.items():
        s = ctx.get(mid)
        if s is None:
            continue
        for raw in raw_list:
            prb_id = raw.get("prb_id")
            if prb_id is None:
                continue
            meta = await meta_cache.get(int(prb_id))
            if meta is None:
                continue

            obs = normalize_sslcert_result(raw, s.target.label, meta.country_code, meta.asn)
            if obs is None:
                continue

            rtt_ms: float | None = None
            rt = raw.get("rt")
            if isinstance(rt, (int, float)):
                rtt_ms = float(rt)

            rows.append(
                ProbeResultRow(
                    measurement_id=mid,
                    probe_id=obs.probe_id,
                    asn=obs.asn,
                    country_code=obs.country_code,
                    target_ip=obs.target_ip,
                    target_port=s.target.port,
                    target_label=obs.target_label,
                    observed_at=obs.observed_at,
                    outcome=obs.outcome,
                    rtt_ms=rtt_ms,
                    raw=raw,
                )
            )
            observations.append(obs)

    return rows, observations


async def run_live_cycle(
    client: AtlasClient,
    targets: list[Target],
    match: Match | None,
    baseline: Mapping[tuple[int, str], BaselineStats],
    cfg: CycleConfig | None = None,
    detection_cfg: DetectionConfig | None = None,
) -> CycleResult:
    """Schedule, poll, normalize. Detect only if `match` is not None.

    A first-run bootstrap where no baseline exists yet should still call this
    with `match=None` (or an empty baseline) so `probe_results` accumulate.
    Subsequent cycles can pass a real match and a DB-loaded baseline.
    """
    cfg = cfg or CycleConfig()

    scheduled = await schedule_cycle(client, targets, cfg)
    raw = await wait_for_results(client, scheduled, cfg)
    meta_cache = ProbeMetaCache(client=client)
    rows, observations = await normalize_cycle(raw, scheduled, meta_cache)

    incidents: list[IncidentRow] = []
    if match is not None and observations:
        incidents = detect_block(observations, match, baseline, detection_cfg)

    return CycleResult(
        scheduled=scheduled,
        rows=rows,
        observations=observations,
        incidents=incidents,
    )


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


# Re-export so callers can import httpx transport errors through one path if desired.
HTTPStatusError = httpx.HTTPStatusError
