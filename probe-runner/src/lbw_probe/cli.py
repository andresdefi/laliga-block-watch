"""CLI entry point.

Commands (planned):
- `lbw-probe run-cycle` - schedule one measurement cycle against the full target list.
- `lbw-probe backfill --weeks N` - replay the last N weekends against historical RIPE Atlas data.
- `lbw-probe detect` - run detection over the latest probe window.

Not implemented.
"""

import typer

app = typer.Typer(no_args_is_help=True, help="laliga-block-watch probe runner")


@app.command()
def version() -> None:
    """Print the package version."""
    from lbw_probe import __version__

    typer.echo(__version__)


if __name__ == "__main__":
    app()
