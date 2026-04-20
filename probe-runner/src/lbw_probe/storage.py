"""Postgres storage layer.

A thin wrapper over psycopg3. All writes go through this module so the schema
is versioned in one place and so we can swap in a different driver (or a
ClickHouse sink for `probe_results`) later without touching the callers.

We deliberately keep this small. The Probe runner writes raw rows; the
detector reads ranges; the API reads incidents. No ORM, no session management
magic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from lbw_probe.schedule import Match

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"


@dataclass(frozen=True)
class ProbeResultRow:
    measurement_id: int
    probe_id: int
    asn: int | None
    country_code: str
    target_ip: str
    target_port: int
    target_label: str
    observed_at: datetime
    outcome: str
    rtt_ms: float | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class IncidentRow:
    target_ip: str
    target_label: str
    match_id: int | None
    started_at: datetime
    ended_at: datetime | None
    affected_asns: list[int]
    evidence: dict[str, Any]


@dataclass
class Storage:
    database_url: str

    async def apply_migrations(self) -> list[str]:
        """Apply every *.sql file in migrations/ in lexical order.

        Idempotent because each migration uses `CREATE TABLE IF NOT EXISTS`
        and `CREATE INDEX IF NOT EXISTS`.
        """
        files = sorted(MIGRATIONS_DIR.glob("*.sql"))
        applied: list[str] = []
        async with await psycopg.AsyncConnection.connect(self.database_url) as conn:
            for f in files:
                sql = f.read_text()
                async with conn.cursor() as cur:
                    # pyright: ignore[reportCallIssue]
                    # psycopg expects LiteralString for safety; migration SQL
                    # is loaded from the repo, not user input, so this is fine.
                    await cur.execute(sql.encode("utf-8"))
                await conn.commit()
                applied.append(f.name)
        return applied

    async def record_probe_results(self, rows: list[ProbeResultRow]) -> int:
        if not rows:
            return 0
        async with await psycopg.AsyncConnection.connect(self.database_url) as conn:
            async with conn.cursor() as cur:
                await cur.executemany(
                    """
                    INSERT INTO probe_results
                        (measurement_id, probe_id, asn, country_code,
                         target_ip, target_port, target_label,
                         observed_at, outcome, rtt_ms, raw)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            r.measurement_id,
                            r.probe_id,
                            r.asn,
                            r.country_code,
                            r.target_ip,
                            r.target_port,
                            r.target_label,
                            r.observed_at,
                            r.outcome,
                            r.rtt_ms,
                            json.dumps(r.raw),
                        )
                        for r in rows
                    ],
                )
            await conn.commit()
        return len(rows)

    async def upsert_matches(self, matches: list[Match]) -> int:
        if not matches:
            return 0
        async with await psycopg.AsyncConnection.connect(self.database_url) as conn:
            async with conn.cursor() as cur:
                await cur.executemany(
                    """
                    INSERT INTO matches (id, kickoff_utc, home, away, status)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE
                        SET kickoff_utc = EXCLUDED.kickoff_utc,
                            home        = EXCLUDED.home,
                            away        = EXCLUDED.away,
                            status      = EXCLUDED.status
                    """,
                    [(m.id, m.kickoff_utc, m.home, m.away, m.status) for m in matches],
                )
            await conn.commit()
        return len(matches)

    async def record_incident(self, incident: IncidentRow) -> int:
        async with await psycopg.AsyncConnection.connect(self.database_url) as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                    INSERT INTO incidents
                        (target_ip, target_label, match_id,
                         started_at, ended_at, affected_asns, evidence)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        incident.target_ip,
                        incident.target_label,
                        incident.match_id,
                        incident.started_at,
                        incident.ended_at,
                        incident.affected_asns,
                        json.dumps(incident.evidence),
                    ),
                )
                row: dict[str, Any] | None = await cur.fetchone()
            await conn.commit()
        if row is None:
            raise RuntimeError("incident insert did not return an id")
        return int(row["id"])

    async def list_verified_user_targets(self) -> list[dict[str, Any]]:
        async with await psycopg.AsyncConnection.connect(self.database_url) as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "SELECT id, url, contact_email, notes, submitted_at "
                    "FROM user_targets WHERE verified = TRUE "
                    "ORDER BY submitted_at DESC"
                )
                rows: list[dict[str, Any]] = list(await cur.fetchall())
        return rows
