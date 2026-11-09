"""Audio content kind: mp3/wav/ogg/m4a/flac, previewed via an <audio> element."""

from __future__ import annotations

from preview_dashboard.kinds.base import PreviewMode, SimpleExtensionKind

_MEDIA_TYPES = {
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
}


class AudioKind(SimpleExtensionKind):
    """mp3/wav/ogg/m4a/flac, rendered via <audio> from the preview origin."""

    name = "audio"
    label = "Audio"
    renderer = "audio"
    preview_mode = PreviewMode.MEDIA
    extensions = frozenset(_MEDIA_TYPES)
    _media_types = _MEDIA_TYPES
