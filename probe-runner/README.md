# probe-runner

Schedules RIPE Atlas measurements against the target list, stores results, and feeds the detection engine.

Status: skeleton only. No module is implemented yet.

## Install

```
cd probe-runner
uv venv
uv pip install -e ".[dev]"
```

## Env

Copy `.env.example` to `.env` at the repo root and fill in:

- `RIPE_ATLAS_API_KEY` - create a measurement key at https://atlas.ripe.net
- `DATABASE_URL` - postgres URL for results

## Layout

- `src/lbw_probe/atlas.py` - RIPE Atlas REST client
- `src/lbw_probe/targets.py` - target list loader (Cloudflare ranges, known services, user submissions)
- `src/lbw_probe/schedule.py` - LaLiga match schedule fetcher
- `src/lbw_probe/detect.py` - null-route detection (TCP-connect timeout signature, control-group comparison)
- `src/lbw_probe/storage.py` - Postgres writer
- `src/lbw_probe/cli.py` - typer entry point
