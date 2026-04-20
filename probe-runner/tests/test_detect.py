"""Tests for detect.detect_block and detect.compute_baseline.

We build synthetic ProbeObservation lists rather than normalizing real Atlas
payloads so each test isolates one gate of the detector. One positive case
proves the full pipeline fires; four negative cases prove each gate blocks on
its own.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lbw_probe.detect import (
    BaselineStats,
    DetectionConfig,
    ProbeObservation,
    compute_baseline,
    detect_block,
    normalize_sslcert_result,
)
from lbw_probe.schedule import Match

KICKOFF = datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)
MATCH = Match(id=42, kickoff_utc=KICKOFF, home="RMA", away="FCB", status="SCHEDULED")
TARGET = "104.16.0.1"
LABEL = "cloudflare:104.16.0.0/24:104.16.0.1"

DURING = KICKOFF + timedelta(minutes=15)


def _healthy_baseline() -> dict[tuple[int, str], BaselineStats]:
    return {
        (3352, TARGET): BaselineStats(
            asn=3352, target_ip=TARGET, success_rate=0.99, sample_size=500
        ),
        (12479, TARGET): BaselineStats(
            asn=12479, target_ip=TARGET, success_rate=0.98, sample_size=500
        ),
    }


def _obs(
    probe_id: int,
    country: str,
    outcome: str,
    asn: int | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        probe_id=probe_id,
        asn=asn,
        country_code=country,
        target_ip=TARGET,
        target_label=LABEL,
        outcome=outcome,  # pyright: ignore[reportArgumentType]
        observed_at=DURING,
    )


def test_detects_clean_spain_block() -> None:
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "timeout", asn=12479),
        _obs(3, "ES", "timeout", asn=3352),
        _obs(10, "PT", "success", asn=3243),
        _obs(11, "FR", "success", asn=5410),
    ]
    incidents = detect_block(obs, MATCH, _healthy_baseline())
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.target_ip == TARGET
    assert inc.match_id == MATCH.id
    assert set(inc.affected_asns) == {3352, 12479}
    assert inc.evidence["spain_timeout_rate"] == 1.0
    assert inc.evidence["control_success_rate"] == 1.0


def test_fails_when_too_few_spain_probes() -> None:
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(10, "PT", "success", asn=3243),
    ]
    assert detect_block(obs, MATCH, _healthy_baseline()) == []


def test_fails_when_no_control_probes() -> None:
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "timeout", asn=12479),
    ]
    assert detect_block(obs, MATCH, _healthy_baseline()) == []


def test_fails_when_control_not_succeeding() -> None:
    """If the target is globally unreachable, no LaLiga incident."""
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "timeout", asn=12479),
        _obs(10, "PT", "timeout", asn=3243),
        _obs(11, "FR", "timeout", asn=5410),
    ]
    assert detect_block(obs, MATCH, _healthy_baseline()) == []


def test_fails_when_baseline_unhealthy() -> None:
    """If the ASN's baseline to this target is already bad, no incident."""
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "timeout", asn=12479),
        _obs(10, "PT", "success", asn=3243),
    ]
    bad = {
        (3352, TARGET): BaselineStats(
            asn=3352, target_ip=TARGET, success_rate=0.20, sample_size=500
        ),
        (12479, TARGET): BaselineStats(
            asn=12479, target_ip=TARGET, success_rate=0.20, sample_size=500
        ),
    }
    assert detect_block(obs, MATCH, bad) == []


def test_fails_when_baseline_sample_too_small() -> None:
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "timeout", asn=12479),
        _obs(10, "PT", "success", asn=3243),
    ]
    thin = {
        (3352, TARGET): BaselineStats(
            asn=3352, target_ip=TARGET, success_rate=0.99, sample_size=3
        ),
    }
    assert detect_block(obs, MATCH, thin) == []


def test_custom_config_tightens_thresholds() -> None:
    """50% timeouts fails when the threshold is 0.8."""
    obs = [
        _obs(1, "ES", "timeout", asn=3352),
        _obs(2, "ES", "success", asn=12479),
        _obs(10, "PT", "success", asn=3243),
    ]
    strict = DetectionConfig(spain_timeout_rate_min=0.8)
    assert detect_block(obs, MATCH, _healthy_baseline(), strict) == []


def test_normalize_sslcert_success() -> None:
    raw = {
        "prb_id": 12345,
        "dst_addr": TARGET,
        "timestamp": int(DURING.timestamp()),
        "cert": ["-----BEGIN CERTIFICATE-----..."],
    }
    obs = normalize_sslcert_result(raw, LABEL, "ES", 3352)
    assert obs is not None
    assert obs.outcome == "success"
    assert obs.target_ip == TARGET
    assert obs.asn == 3352
    assert obs.country_code == "ES"


def test_normalize_sslcert_timeout() -> None:
    raw = {
        "prb_id": 12345,
        "dst_addr": TARGET,
        "timestamp": int(DURING.timestamp()),
        "err": "connect: timeout",
    }
    obs = normalize_sslcert_result(raw, LABEL, "ES", 3352)
    assert obs is not None
    assert obs.outcome == "timeout"


def test_normalize_sslcert_refused() -> None:
    raw = {
        "prb_id": 12345,
        "dst_addr": TARGET,
        "timestamp": int(DURING.timestamp()),
        "err": "connection refused",
    }
    obs = normalize_sslcert_result(raw, LABEL, "ES", 3352)
    assert obs is not None
    assert obs.outcome == "refused"


def test_normalize_sslcert_missing_field_returns_none() -> None:
    assert normalize_sslcert_result({}, LABEL, "ES", 3352) is None


def test_compute_baseline_excludes_match_windows_and_null_asn() -> None:
    def in_window(ts: datetime) -> bool:
        return KICKOFF - timedelta(minutes=30) <= ts <= KICKOFF + timedelta(minutes=150)

    before = KICKOFF - timedelta(hours=6)
    during = KICKOFF + timedelta(minutes=15)

    hist = [
        ProbeObservation(1, 3352, "ES", TARGET, LABEL, "success", before),
        ProbeObservation(1, 3352, "ES", TARGET, LABEL, "success", before),
        ProbeObservation(1, 3352, "ES", TARGET, LABEL, "timeout", before),
        ProbeObservation(2, 3352, "ES", TARGET, LABEL, "timeout", during),
        ProbeObservation(3, None, "ES", TARGET, LABEL, "success", before),
    ]
    stats = compute_baseline(hist, in_window)
    assert (3352, TARGET) in stats
    s = stats[(3352, TARGET)]
    assert s.sample_size == 3
    assert abs(s.success_rate - (2 / 3)) < 1e-9
