"""SVG content kind: served as image/svg+xml, but only ever via <img>.

SVG can carry <script> and event-handler attributes. It's still MEDIA
(not SANDBOXED like html) because the preview UI renders it with an
<img> tag, which never executes embedded scripts — unlike an <object>,
<embed> or direct navigation (docs/security.md C5: "SVG is shown only via
<img>").
"""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {".svg": "image/svg+xml"}


class SvgKind(SimpleExtensionKind):
    """SVG images, rendered only via <img> from the preview origin."""

    name = "svg"
    label = "SVG image"
    renderer = "svg"
    preview_mode = PreviewMode.MEDIA
    extensions = frozenset(_MEDIA_TYPES)
    _media_types = _MEDIA_TYPES
