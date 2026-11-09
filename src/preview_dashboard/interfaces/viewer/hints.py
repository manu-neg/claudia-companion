"""Per-response hints a preview route passes to the preview app's header middleware.

Routes record *what* they are serving (the item kind's preview mode, and
whether the file is a sub-resource of an HTML bundle); the middleware alone
decides the CSP, CORP and fetch-metadata verdict from that plus the
response's own Content-Type. No hints means the strictest policy (fail closed).

Bundle sub-resources are additionally *bound* to their own bundle: they are
only treated as loadable cross-site (CORP `cross-origin`) when the request's
`Referer` is a page of the same item **and the same revision URL segment**
on the preview origin (ADR 0012, ADR 0019).
"""

from __future__ import annotations

from dataclasses import dataclass

from starlette.types import Scope

from preview_dashboard.interfaces.viewer._http import header_values
from preview_dashboard.kinds.base import PreviewMode

_HINTS_KEY = "pdash.preview_hints"
# Path prefix of inline item bytes on the preview app: `/i/<item id>/<rev>/<relpath>`.
PREVIEW_ITEM_PREFIX = "/i/"


@dataclass(frozen=True, slots=True)
class PreviewHints:
    """What a preview route is serving.

    Attributes:
        preview_mode: the item kind's `PreviewMode`, or None if unknown
            (errors). Only `DOCUMENT` relaxes anything (the PDF exception).
        bundle_subresource: True only for a non-entry file of an `html`
            bundle, fetched by the bundle's own sandboxed (opaque-origin)
            document; see ADR 0012 for why this changes CORP/fetch metadata.
        item_id: the item being served. Required for a bundle sub-resource
            to ever be bound to its bundle (`bundle_referer_bound`).
        revision: the revision segment exactly as in the request URL (a
            number, or `latest`). Also required for the binding: a page of
            one revision can't pull sub-resources of another.
    """

    preview_mode: PreviewMode | None = None
    bundle_subresource: bool = False
    item_id: str | None = None
    revision: str | None = None


STRICTEST = PreviewHints()


def set_preview_hints(scope: Scope, hints: PreviewHints) -> None:
    """Record `hints` for the current request (call before returning the response)."""
    scope.setdefault("state", {})[_HINTS_KEY] = hints


def get_preview_hints(scope: Scope) -> PreviewHints:
    """Return the recorded hints, or `STRICTEST` if none (or garbage) was set."""
    state = scope.get("state")
    value = state.get(_HINTS_KEY) if isinstance(state, dict) else None
    return value if isinstance(value, PreviewHints) else STRICTEST


def bundle_referer_bound(scope: Scope, hints: PreviewHints, preview_origin: str) -> bool:
    """True iff a bundle sub-resource was requested by a page of its own bundle revision.

    Requires `hints.bundle_subresource`, an `item_id`, a `revision`, and
    exactly one ASCII `Referer` starting with
    `<preview_origin>/i/<item_id>/<revision>/`. The bundle's pages are
    served with `Referrer-Policy: same-origin`, so their own loads carry
    that Referer; an attacker page cannot forge it, and a browser that
    strips it fails closed (CORP `same-site`, cross-site 403).
    """
    if (
        not hints.bundle_subresource
        or not hints.item_id
        or not hints.revision
        or not preview_origin
    ):
        return False
    values = header_values(scope, b"referer")
    if len(values) != 1:
        return False
    try:
        referer = values[0].decode("ascii").strip()
    except UnicodeDecodeError:
        return False
    prefix = f"{preview_origin}{PREVIEW_ITEM_PREFIX}{hints.item_id}/{hints.revision}/"
    return referer.startswith(prefix)
