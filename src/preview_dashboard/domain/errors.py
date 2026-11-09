"""Domain error hierarchy.

Every error the core raises on purpose derives from `DomainError`, so
interfaces can map the whole family to HTTP/MCP responses in one place.
Messages are safe to show to the caller (no paths on disk, no secrets).
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for all intentional domain/application errors."""


class ValidationError(DomainError):
    """Input violates a domain invariant (bad title, id, cursor, ...)."""


class InvalidPathError(ValidationError):
    """A bundle-relative path is unsafe or non-canonical (docs/security.md C7)."""


class NotFoundError(DomainError):
    """The requested item or blob does not exist."""


class AlreadyExistsError(DomainError):
    """An entity with the same identity already exists (e.g. duplicate item id)."""


class ConflictError(DomainError):
    """A concurrent writer changed the entity since it was read (optimistic concurrency).

    Raised by `ItemRepository.save` when the stored `updated_at` no longer
    equals the caller's `expected_updated_at`; interfaces answer 409 and the
    client re-reads before retrying (docs/security.md C11).
    """


class LimitExceededError(DomainError):
    """A size or count limit was exceeded (file bytes, item bytes, file count)."""


class RateLimitedError(LimitExceededError):
    """A rate limit (not a size/count budget) refused the operation; retry later.

    A subclass so callers that only care about "a limit" still catch it,
    while interfaces can answer 429 instead of 413 (docs/security.md C18).
    """


class InvalidStateError(DomainError):
    """An operation is illegal in the entity's current state (e.g. trash twice)."""


class UnsupportedContentError(DomainError):
    """Content does not match any registered kind, or fails the kind's checks."""


class SecretDetectedError(DomainError):
    """Published content matches a secret-format rule (docs/security.md C15).

    The message names the rule (and file, if known) but never the matched
    bytes, so the secret cannot leak through error responses or logs.

    Attributes:
        rule: neutral label of the matching rule, e.g. `AWS access key id`
            (never a fragment of the secret itself).
        relpath: bundle-relative path of the offending file, or None.
    """

    def __init__(self, rule: str, relpath: str | None = None) -> None:
        self.rule = rule
        self.relpath = relpath
        where = f" in {relpath!r}" if relpath is not None else ""
        super().__init__(f"content{where} matches secret rule {rule!r}; publish rejected")


class StorageUnavailableError(DomainError):
    """Storage refused to serve safely right now (server-side, not the caller's input).

    E.g. an on-disk entry failed its ownership/mode checks (docs/security.md
    C24). The core fails closed; interfaces answer 503 + Retry-After so
    clients back off and retry instead of treating it as bad input (ADR 0025).
    """
