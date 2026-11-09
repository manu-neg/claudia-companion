# ADR 0001: Hexagonal architecture (ports & adapters)

**TL;DR:** Domain and application logic depend only on Protocol-based ports, never on frameworks or concrete adapters, so the core is unit-testable in isolation and storage/interfaces can change independently.

## Context

The dashboard has four processes (viewer, admin, mcp, purge) that all need the same core logic (publish, query, trash/restore, purge), backed by SQLite and a filesystem blob store today, with the plan to add content kinds and possibly storage backends over time. Requirements call for "very clean, SOLID code, known patterns, easy to extend," with security-relevant logic (path validation, limits, state transitions) that must be testable without spinning up a database or an HTTP server.

## Decision

Adopt a hexagonal (ports & adapters) architecture:

- `domain/` holds entities and pure logic (Item, ItemFile, the trash/restore state machine, safe-path construction). No framework imports.
- `ports/` defines `typing.Protocol` interfaces (`ItemRepository`, `BlobStore`, `Clock`, `IdGenerator`) that `application/` depends on.
- `application/` holds use-case services (publish, queries, lifecycle, purge, archive) that orchestrate domain logic via ports. No framework imports.
- `adapters/` implements ports against real infrastructure (SQLite, filesystem, wall clock, ULID generator).
- `interfaces/` (viewer HTTP, admin HTTP, MCP, CLI) translates external requests into application-service calls and maps domain errors to HTTP/MCP responses.
- `bootstrap.py` is the single composition root: the only module allowed to import both `application/` and `adapters/` and wire them together.

## Consequences

- Application and domain logic get full unit-test coverage with in-memory fakes (`tests/fakes.py`), no I/O required.
- Adding a storage backend or a new interface never requires touching `domain/` or `application/` — enforced by the "no framework imports" rule and checked in code review / security audits.
- Slightly more indirection (Protocols, constructor injection everywhere) than a framework-coupled approach — accepted as the cost of testability and the plan's explicit "easy to extend" requirement.
- Port contract tests (same suite run against fakes and real adapters) become mandatory whenever a new adapter is added, to prevent the fake and the real implementation from drifting apart.
