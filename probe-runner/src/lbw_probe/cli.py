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


if __name__ == "__main__":
    app()
