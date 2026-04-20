"""CLI entry point.

Each command is intentionally small. Anything non-trivial lives in the other
modules and is import-tested independently.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer
from dotenv import load_dotenv

from lbw_probe.orchestrator import (
    build_plan,
    load_fixture,
    plan_summary,
    replay_fixture,
)
from lbw_probe.schedule import fetch_matches
from lbw_probe.storage import Storage
from lbw_probe.targets import (
    KNOWN_AFFECTED_SERVICES,
    fetch_cloudflare_v4_ranges,
    resolve_known_services,
    targets_from_cidrs,
)

app = typer.Typer(no_args_is_help=True, help="laliga-block-watch probe runner")


def _load_env() -> None:
    root_env = Path(__file__).resolve().parents[3] / ".env"
    if root_env.exists():
        load_dotenv(root_env)


def _require(var: str) -> str:
    v = os.environ.get(var)
    if not v:
        typer.echo(f"error: {var} is not set", err=True)
        raise typer.Exit(code=2)
    return v


@app.command()
def version() -> None:
    """Print the package version."""
    from lbw_probe import __version__

    typer.echo(__version__)


@app.command()
def migrate() -> None:
    """Apply SQL migrations to the configured DATABASE_URL."""
    _load_env()
    db_url = _require("DATABASE_URL")
    storage = Storage(database_url=db_url)
    applied = asyncio.run(storage.apply_migrations())
    for name in applied:
        typer.echo(f"applied {name}")


@app.command("refresh-schedule")
def refresh_schedule() -> None:
    """Fetch LaLiga fixtures from football-data.org and upsert into matches."""
    _load_env()
    db_url = _require("DATABASE_URL")
    token = _require("FOOTBALL_DATA_API_KEY")
    storage = Storage(database_url=db_url)

    async def _run() -> int:
        matches = await fetch_matches(api_token=token)
        return await storage.upsert_matches(matches)

    n = asyncio.run(_run())
    typer.echo(f"upserted {n} matches")


@app.command("refresh-targets")
def refresh_targets(
    include_known_services: bool = typer.Option(
        True, help="Resolve and include the seeded known-affected services."
    ),
) -> None:
    """Build and print the probe target list (does not write to DB)."""
    _load_env()

    async def _run() -> tuple[int, int]:
        cidrs = await fetch_cloudflare_v4_ranges()
        cf_targets = targets_from_cidrs(cidrs)
        service_targets = (
            await resolve_known_services(KNOWN_AFFECTED_SERVICES)
            if include_known_services
            else []
        )
        return len(cf_targets), len(service_targets)

    cf_count, svc_count = asyncio.run(_run())
    typer.echo(f"cloudflare_sample targets: {cf_count}")
    typer.echo(f"known_service targets:     {svc_count}")


@app.command("dry-run")
def dry_run(
    probes_per_region: int = typer.Option(
        3, help="Probes to schedule per region per target."
    ),
    include_known_services: bool = typer.Option(True),
) -> None:
    """Print what a live measurement cycle would schedule. No Atlas calls."""
    _load_env()

    async def _run() -> int:
        cidrs = await fetch_cloudflare_v4_ranges()
        cf_targets = targets_from_cidrs(cidrs)
        service_targets = (
            await resolve_known_services(KNOWN_AFFECTED_SERVICES)
            if include_known_services
            else []
        )
        all_targets = cf_targets + service_targets
        plan = build_plan(all_targets, probes_per_region=probes_per_region)
        typer.echo(plan_summary(plan))
        return plan.total_probe_observations

    asyncio.run(_run())


@app.command()
def replay(
    fixture: Path = typer.Argument(..., help="Path to JSON fixture bundle."),
    write: bool = typer.Option(
        False, "--write", help="Persist detected incidents to DATABASE_URL."
    ),
) -> None:
    """Run the detector over a recorded/synthetic observations fixture."""
    _load_env()
    bundle = load_fixture(fixture)
    incidents = replay_fixture(bundle)
    typer.echo(f"detected {len(incidents)} incident(s)")
    for inc in incidents:
        rate = float(inc.evidence.get("spain_timeout_rate", 0.0))
        typer.echo(
            f"  - {inc.target_label} "
            f"asns={inc.affected_asns} "
            f"spain_timeout={rate:.0%}"
        )
    if write and incidents:
        db_url = _require("DATABASE_URL")
        storage = Storage(database_url=db_url)

        async def _persist() -> int:
            n = 0
            for inc in incidents:
                await storage.record_incident(inc)
                n += 1
            return n

        n = asyncio.run(_persist())
        typer.echo(f"wrote {n} incident(s) to DB")


if __name__ == "__main__":
    app()
