"""Ports: `typing.Protocol` interfaces the application layer depends on.

Adapters (SQLite, filesystem, wall clock, ULID) implement these; in-memory
fakes in `tests/fakes.py` implement them for unit tests. Pure stdlib only.
"""
