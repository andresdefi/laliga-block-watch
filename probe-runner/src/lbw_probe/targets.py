"""Target list management.

Loads the set of (IP, port, label) tuples we probe on every cycle:
- Cloudflare published IPv4/IPv6 ranges, sampled 1 IP per /24.
- Known affected consumer services (PAJ Portal, Securitas, Glovo, Docker, etc.).
- User-submitted services from the Postgres `user_targets` table.

Not implemented.
"""
