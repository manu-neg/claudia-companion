"""Piper text-to-speech adapter: local synthesis to an Ogg/Opus voice note (C56, unit M10).

Implements `ports.claudia_voice.TextToSpeech` with the optional `claudia-voice`
extra (piper-tts, soundfile, numpy), imported lazily so the base install works
without it. Models are loaded only from a configured directory (never
downloaded: no network), audio stays in memory (no temp files) and is
resampled 22.05 -> 24 kHz because Opus has no 22.05 kHz mode. piper-tts is
GPL-3.0: a runtime dependency only, never vendored.
"""

from __future__ import annotations

import importlib
import io
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, Final

from preview_dashboard.domain.errors import StorageUnavailableError, ValidationError

# Owner-picked voices (V6): Spanish (Mexico) and English (US).
DEFAULT_VOICES: Final = {"es": "es_MX-claude-high", "en": "en_US-amy-medium"}
OPUS_RATE: Final = 24_000
_MAX_CHUNKS: Final = 2_000  # a bound on what one synthesis may yield


def _import(name: str) -> ModuleType:
    """Import an optional dependency, failing closed with a clear, non-leaky error."""
    try:
        return importlib.import_module(name)
    except ImportError:
        raise StorageUnavailableError(
            "voice synthesis needs the 'claudia-voice' extra (uv sync --extra claudia-voice)"
        ) from None


class PiperTextToSpeech:
    """Speaks text with Piper voices found in `models_dir` (`<voice>.onnx` + `.onnx.json`).

    Args:
        models_dir: directory holding the voice models (root-owned, configured).
        voices: language -> voice name (default `DEFAULT_VOICES`).
    """

    def __init__(self, models_dir: Path, voices: dict[str, str] | None = None) -> None:
        self._dir = models_dir
        self._voices = dict(DEFAULT_VOICES if voices is None else voices)
        # Typed Any: piper has no stubs (justified; contained to this module).
        self._loaded: dict[str, Any] = {}
        # Piper voices are not documented as thread-safe; one synthesis at a time.
        self._lock = threading.Lock()

    def synthesize(self, text: str, language: str) -> bytes:
        """Ogg/Opus bytes (24 kHz mono) of `text` in `language`.

        Raises:
            ValidationError: unknown language or empty text.
            StorageUnavailableError: the extra, the model or the engine is missing or failed.
        """
        name = self._voices.get(language)
        if name is None:
            raise ValidationError("unsupported voice language")
        if not text.strip():
            raise ValidationError("nothing to speak")
        np = _import("numpy")
        sf = _import("soundfile")
        with self._lock:
            try:
                voice = self._voice(name)
                parts = []
                rate = 0
                for index, chunk in enumerate(voice.synthesize(text)):
                    if index >= _MAX_CHUNKS:
                        raise StorageUnavailableError("speech synthesis produced too much audio")
                    parts.append(chunk.audio_int16_array)
                    rate = int(chunk.sample_rate)
                if not parts or rate <= 0:
                    raise StorageUnavailableError("speech synthesis produced no audio")
                samples = np.concatenate(parts).astype("float32") / 32768.0
                samples = _resample(np, samples, rate, OPUS_RATE)
                buffer = io.BytesIO()
                sf.write(buffer, samples, OPUS_RATE, format="OGG", subtype="OPUS")
            except StorageUnavailableError:
                raise
            except Exception:  # engine failures vary (onnx, soundfile); none may leak details
                raise StorageUnavailableError("speech synthesis failed") from None
        return buffer.getvalue()

    def _voice(self, name: str) -> Any:  # noqa: ANN401  (piper is untyped, optional)
        if name not in self._loaded:
            model = self._dir / f"{name}.onnx"
            if not model.is_file():
                raise StorageUnavailableError("voice model not installed")
            piper = _import("piper")
            self._loaded[name] = piper.PiperVoice.load(model)
        return self._loaded[name]


def _resample(np: Any, samples: Any, source: int, target: int) -> Any:  # noqa: ANN401
    # Any: numpy is an optional, lazily imported dependency.
    """Linear-interpolation resample (speech at 22.05 -> 24 kHz needs nothing fancier)."""
    if source == target:
        return samples
    count = max(1, round(len(samples) * target / source))
    positions = np.linspace(0, len(samples) - 1, num=count)
    return np.interp(positions, np.arange(len(samples)), samples).astype("float32")
