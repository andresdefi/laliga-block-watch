"""Null-route detection.

The detector treats RIPE Atlas results as opaque JSON and normalizes them into
`ProbeObservation`s first. Every detection rule is then a pure function over
those observations plus a precomputed baseline. This split matters because the
public dashboard will show evidence bundles that a regulator must be able to
replay by hand - so the rules have to be small, readable, and side-effect
free.

A null-route incident fires when all four of these hold for a target IP
during a LaLiga match window:

1. At least N Spanish probes observed the target; of those, at least X% saw a
   TCP-connect timeout (not RST, not TLS failure).
2. At least N control probes (PT / FR) observed the target; of those, at
   least Y% saw success.
3. For at least one of the Spanish ASNs whose probes timed out, the 30-day
   non-match baseline for (ASN, target_ip) shows the route is normally
   healthy. This gates out "the service is just always broken".
4. The observation timestamps fall inside the match window (the caller is
   expected to filter to that window before invoking `detect_block`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Literal, Mapping

from lbw_probe.schedule import Match
from lbw_probe.storage import IncidentRow

Outcome = Literal["success", "timeout", "refused", "other"]


@dataclass(frozen=True)
class ProbeObservation:
    """Normalized probe result, agnostic of RIPE Atlas wire format."""

    probe_id: int
    asn: int | None
    country_code: str
    target_ip: str
    target_label: str
    outcome: Outcome
    observed_at: datetime


@dataclass(frozen=True)
class BaselineStats:
    asn: int
    target_ip: str
    success_rate: float
    sample_size: int


@dataclass(frozen=True)
class DetectionConfig:
    min_spain_probes: int = 2
    min_control_probes: int = 1
    spain_timeout_rate_min: float = 0.5
    control_success_rate_min: float = 0.5
    baseline_healthy_min: float = 0.8
    baseline_min_samples: int = 10
    spain_country_code: str = "ES"
    control_country_codes: frozenset[str] = field(
        default_factory=lambda: frozenset({"PT", "FR"})
    )


def normalize_sslcert_result(
    raw: dict[str, Any],
    target_label: str,
    probe_country: str,
    probe_asn: int | None,
) -> ProbeObservation | None:
    """Turn one RIPE Atlas sslcert measurement result into a ProbeObservation.

    Returns None if the record is missing a required field (we'd rather drop
    one measurement than record a garbage outcome).
    """
    try:
        probe_id = int(raw["prb_id"])
        target_ip = str(raw["dst_addr"])
        ts = datetime.fromtimestamp(int(raw["timestamp"]))
    except (KeyError, TypeError, ValueError):
        return None

    outcome: Outcome
    if raw.get("cert"):
        outcome = "success"
    else:
        err = str(raw.get("err", "")).lower()
        if "timeout" in err:
            outcome = "timeout"
        elif "refused" in err or "reset" in err:
            outcome = "refused"
        else:
            outcome = "other"

    return ProbeObservation(
        probe_id=probe_id,
        asn=probe_asn,
        country_code=probe_country.upper(),
        target_ip=target_ip,
        target_label=target_label,
        outcome=outcome,
        observed_at=ts,
    )


def compute_baseline(
    historical: Iterable[ProbeObservation],
    is_in_match_window: Callable[[datetime], bool],
) -> dict[tuple[int, str], BaselineStats]:
    """Compute per-(ASN, target_ip) success rate across non-match observations.

    Observations with no ASN are ignored; baseline needs ASN-level granularity
    to make condition (3) of detect_block meaningful.
    """
    from collections import defaultdict

    counters: dict[tuple[int, str], dict[str, int]] = defaultdict(
        lambda: {"success": 0, "total": 0}
    )
    for o in historical:
        if o.asn is None:
            continue
        if is_in_match_window(o.observed_at):
            continue
        key = (o.asn, o.target_ip)
        counters[key]["total"] += 1
        if o.outcome == "success":
            counters[key]["success"] += 1

    out: dict[tuple[int, str], BaselineStats] = {}
    for (asn, target_ip), c in counters.items():
        rate = c["success"] / c["total"] if c["total"] else 0.0
        out[(asn, target_ip)] = BaselineStats(
            asn=asn,
            target_ip=target_ip,
            success_rate=rate,
            sample_size=c["total"],
        )
    return out


def detect_block(
    observations: Iterable[ProbeObservation],
    match: Match,
    baseline: Mapping[tuple[int, str], BaselineStats],
    config: DetectionConfig | None = None,
) -> list[IncidentRow]:
    """Pure function. Return one IncidentRow per target IP that trips all gates.

    The caller is responsible for handing us only observations whose
    `observed_at` falls inside `match.window()`. We do not re-filter here
    because we want the caller to be explicit about the window being tested.
    """
    cfg = config or DetectionConfig()

    by_target: dict[str, list[ProbeObservation]] = {}
    labels: dict[str, str] = {}
    for o in observations:
        by_target.setdefault(o.target_ip, []).append(o)
        labels[o.target_ip] = o.target_label

    incidents: list[IncidentRow] = []
    for target_ip, obs in by_target.items():
        spain = [o for o in obs if o.country_code == cfg.spain_country_code]
        control = [o for o in obs if o.country_code in cfg.control_country_codes]

        if len(spain) < cfg.min_spain_probes:
            continue
        if len(control) < cfg.min_control_probes:
            continue

        spain_timeouts = [o for o in spain if o.outcome == "timeout"]
        control_successes = [o for o in control if o.outcome == "success"]

        spain_timeout_rate = len(spain_timeouts) / len(spain)
        control_success_rate = len(control_successes) / len(control)

        if spain_timeout_rate < cfg.spain_timeout_rate_min:
            continue
        if control_success_rate < cfg.control_success_rate_min:
            continue

        affected_asns = sorted(
            {o.asn for o in spain_timeouts if o.asn is not None}
        )
        healthy_asn = next(
            (
                asn
                for asn in affected_asns
                if (stats := baseline.get((asn, target_ip))) is not None
                and stats.sample_size >= cfg.baseline_min_samples
                and stats.success_rate >= cfg.baseline_healthy_min
            ),
            None,
        )
        if healthy_asn is None:
            continue

        started_at = min(o.observed_at for o in spain_timeouts)
        ended_at = max(o.observed_at for o in spain_timeouts)

        incidents.append(
            IncidentRow(
                target_ip=target_ip,
                target_label=labels[target_ip],
                match_id=match.id,
                started_at=started_at,
                ended_at=ended_at,
                affected_asns=affected_asns,
                evidence={
                    "spain_probe_count": len(spain),
                    "spain_timeout_rate": spain_timeout_rate,
                    "control_probe_count": len(control),
                    "control_success_rate": control_success_rate,
                    "baseline_reference_asn": healthy_asn,
                    "baseline_reference_success_rate": baseline[
                        (healthy_asn, target_ip)
                    ].success_rate,
                    "match": {
                        "id": match.id,
                        "home": match.home,
                        "away": match.away,
                        "kickoff_utc": match.kickoff_utc.isoformat(),
                    },
                    "config": {
                        "min_spain_probes": cfg.min_spain_probes,
                        "min_control_probes": cfg.min_control_probes,
                        "spain_timeout_rate_min": cfg.spain_timeout_rate_min,
                        "control_success_rate_min": cfg.control_success_rate_min,
                        "baseline_healthy_min": cfg.baseline_healthy_min,
                        "baseline_min_samples": cfg.baseline_min_samples,
                        "spain_country_code": cfg.spain_country_code,
                        "control_country_codes": sorted(cfg.control_country_codes),
                    },
                },
            )
        )
    return incidents
