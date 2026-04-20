# laliga-block-watch

Transparency dashboard that detects, in real time, which internet services are collaterally blocked in Spain by LaLiga's anti-piracy IP blocking orders, and produces court-admissible evidence for affected citizens.

Status: early scaffolding. Nothing runs yet.

## What it is

- A measurement pipeline that probes the Spanish internet from multiple ASNs via RIPE Atlas and compares against a non-Spain control group.
- A detection engine that correlates reachability drops with the LaLiga match schedule.
- A public, citizen-facing site to answer "is my service blocked right now?" and a public API for journalists and regulators.
- A complaint generator that produces signed PDF filings for CNMC and Defensor del Pueblo.

## What it is not

This project ships zero circumvention tooling. No VPN, no proxy, no DNS tricks. It is purely observational.

## Why

See [CLAUDE.md](./CLAUDE.md) for project context, motivation, and architecture.

## License

MIT
