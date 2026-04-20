"""LaLiga match schedule.

The detection engine needs a cheap way to ask "was timestamp T inside a LaLiga
broadcast window?". We pull fixtures from the football-data.org free API
(competition code `PD` for Primera Division) and expose a pure
`is_match_window()` function that the rest of the code can use without making
any network calls.

The block window we use by default starts 30 minutes before kickoff and lasts
150 minutes (90 minute match + stoppage + post-whistle tail). Reports from
users and from adslzone indicate blocks routinely persist well past the final
whistle on weekends; the 150-minute tail is conservative on purpose so we do
not under-count incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import httpx

FOOTBALL_DATA_BASE_URL = "https://api.football-data.org/v4"
PRIMERA_DIVISION_CODE = "PD"

DEFAULT_PRE_KICKOFF = timedelta(minutes=30)
DEFAULT_POST_KICKOFF = timedelta(minutes=150)


@dataclass(frozen=True)
class Match:
    id: int
    kickoff_utc: datetime
    home: str
    away: str
    status: str

    def window(
        self,
        pre: timedelta = DEFAULT_PRE_KICKOFF,
        post: timedelta = DEFAULT_POST_KICKOFF,
    ) -> tuple[datetime, datetime]:
        return (self.kickoff_utc - pre, self.kickoff_utc + post)


def parse_match(raw: dict[str, Any]) -> Match:
    """Parse one match record from the football-data.org v4 response.

    Expected shape (trimmed):
        {
          "id": 12345,
          "utcDate": "2026-04-25T19:00:00Z",
          "status": "SCHEDULED" | "FINISHED" | ...,
          "homeTeam": {"shortName": "Real Madrid", ...},
          "awayTeam": {"shortName": "Barcelona", ...},
        }
    """
    kickoff = datetime.fromisoformat(raw["utcDate"].replace("Z", "+00:00"))
    if kickoff.tzinfo is None:
        kickoff = kickoff.replace(tzinfo=timezone.utc)
    return Match(
        id=int(raw["id"]),
        kickoff_utc=kickoff,
        home=str(raw["homeTeam"].get("shortName") or raw["homeTeam"].get("name") or ""),
        away=str(raw["awayTeam"].get("shortName") or raw["awayTeam"].get("name") or ""),
        status=str(raw.get("status", "")),
    )


def is_match_window(
    matches: Iterable[Match],
    ts: datetime,
    pre: timedelta = DEFAULT_PRE_KICKOFF,
    post: timedelta = DEFAULT_POST_KICKOFF,
) -> Match | None:
    """Return the Match whose broadcast window contains `ts`, or None.

    Pure function. If multiple windows overlap (uncommon but possible in
    back-to-back Saturday slots), the first match found is returned.
    """
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    for m in matches:
        start, end = m.window(pre, post)
        if start <= ts <= end:
            return m
    return None


async def fetch_matches(
    api_token: str,
    competition_code: str = PRIMERA_DIVISION_CODE,
    status_filter: str | None = None,
    timeout_s: float = 15.0,
) -> list[Match]:
    """Fetch fixtures from football-data.org.

    A free API token is required (register at football-data.org). Raises on
    non-2xx. We never swallow errors here because a silently empty schedule
    would turn the detector into a dumb "everything is blocked" alarm.
    """
    headers = {"X-Auth-Token": api_token}
    params: dict[str, str] = {}
    if status_filter is not None:
        params["status"] = status_filter

    async with httpx.AsyncClient(timeout=timeout_s) as client:
        resp = await client.get(
            f"{FOOTBALL_DATA_BASE_URL}/competitions/{competition_code}/matches",
            headers=headers,
            params=params,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        raw_matches: list[dict[str, Any]] = list(data.get("matches", []))
        return [parse_match(m) for m in raw_matches]
