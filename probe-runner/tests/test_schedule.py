"""Pure-function tests for schedule."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lbw_probe.schedule import (
    DEFAULT_POST_KICKOFF,
    DEFAULT_PRE_KICKOFF,
    Match,
    is_match_window,
    parse_match,
)


def _match_at(kickoff: datetime, mid: int = 1) -> Match:
    return Match(
        id=mid,
        kickoff_utc=kickoff,
        home="RMA",
        away="FCB",
        status="SCHEDULED",
    )


def test_parse_match_uses_short_name_when_present() -> None:
    raw = {
        "id": 42,
        "utcDate": "2026-04-25T19:00:00Z",
        "status": "SCHEDULED",
        "homeTeam": {"shortName": "Real Madrid", "name": "Real Madrid CF"},
        "awayTeam": {"shortName": "Barcelona", "name": "FC Barcelona"},
    }
    m = parse_match(raw)
    assert m.id == 42
    assert m.home == "Real Madrid"
    assert m.away == "Barcelona"
    assert m.kickoff_utc == datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)


def test_parse_match_falls_back_to_name() -> None:
    raw = {
        "id": 7,
        "utcDate": "2026-04-25T19:00:00Z",
        "status": "SCHEDULED",
        "homeTeam": {"name": "Getafe CF"},
        "awayTeam": {"name": "Sevilla FC"},
    }
    m = parse_match(raw)
    assert m.home == "Getafe CF"
    assert m.away == "Sevilla FC"


def test_is_match_window_inside_range() -> None:
    kickoff = datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)
    matches = [_match_at(kickoff)]
    assert is_match_window(matches, kickoff) is not None
    # 10 minutes in
    assert is_match_window(matches, kickoff + timedelta(minutes=10)) is not None
    # right at the start edge
    assert is_match_window(matches, kickoff - DEFAULT_PRE_KICKOFF) is not None
    # right at the end edge
    assert is_match_window(matches, kickoff + DEFAULT_POST_KICKOFF) is not None


def test_is_match_window_outside_range() -> None:
    kickoff = datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)
    matches = [_match_at(kickoff)]
    # 1 minute before the pre-window
    assert is_match_window(matches, kickoff - DEFAULT_PRE_KICKOFF - timedelta(minutes=1)) is None
    # 1 minute after the post-window
    assert is_match_window(matches, kickoff + DEFAULT_POST_KICKOFF + timedelta(minutes=1)) is None


def test_is_match_window_returns_first_overlap() -> None:
    k1 = datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)
    k2 = k1 + timedelta(minutes=30)
    matches = [_match_at(k1, 1), _match_at(k2, 2)]
    hit = is_match_window(matches, k1 + timedelta(minutes=40))
    assert hit is not None
    assert hit.id == 1


def test_is_match_window_naive_timestamp_is_treated_as_utc() -> None:
    kickoff = datetime(2026, 4, 25, 19, 0, tzinfo=timezone.utc)
    matches = [_match_at(kickoff)]
    naive = datetime(2026, 4, 25, 19, 10)
    assert is_match_window(matches, naive) is not None
