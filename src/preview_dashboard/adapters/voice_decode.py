"""Sandboxed voice-note decode (docs/security.md C62): Ogg/Opus -> 16 kHz mono PCM16 WAV.

Run only inside the transcription sandbox (`whisper_sandbox.py`), as
`<venv python> -I -B -m preview_dashboard.adapters.voice_decode /tmp/in.ogg`,
input bound read-only, the WAV on stdout. libsndfile (via `soundfile`, the
`claudia-voice` extra) parses the audio only here: its open CVEs sit in the
WAV/AIFF/MAT4/MPEG parsers, so the C61 Ogg/Opus content check runs first and
anything else is refused before libsndfile sees a byte. Output is capped at
130 s. Exit 0 = WAV written; 3 = refused or failed (fixed stderr line, no
content).
"""

from __future__ import annotations

import importlib
import io
import sys
import wave
from collections.abc import Sequence
from typing import Any, Final

from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_media import (
    VOICE_MAX_BYTES,
    VOICE_MAX_SECONDS,
    check_ogg_opus,
)

TARGET_RATE: Final = 16_000
MAX_WAV_SECONDS: Final = 130
WAV_HEADER_BYTES: Final = 44
WAV_MAX_BYTES: Final = WAV_HEADER_BYTES + MAX_WAV_SECONDS * TARGET_RATE * 2
_MAX_CHANNELS: Final = 2
_MAX_INPUT_RATE: Final = 48_000
_FIR_HALF: Final = 32
EXIT_REFUSED: Final = 3


def check_opus_input(data: object) -> bytes:
    """The C61 content check, before any decoder runs: one Ogg/Opus stream, <= 2 MiB, <= 120 s.

    Raises:
        ValidationError: anything else (WAV, Vorbis, FLAC, truncated, too long, ...).
    """
    if not isinstance(data, bytes):
        raise ValidationError("voice must be bytes")
    check_ogg_opus(data, max_bytes=VOICE_MAX_BYTES, max_seconds=VOICE_MAX_SECONDS, what="voice")
    return data


def _resample(np: Any, samples: Any, source: int, target: int) -> Any:  # noqa: ANN401
    # Any: numpy is an optional, lazily imported dependency (claudia-voice extra).
    """Windowed-sinc low-pass below the target Nyquist, then linear interpolation."""
    if source == target:
        return samples
    if target < source:
        cutoff = 0.45 * target / source  # cycles per input sample
        n = np.arange(-_FIR_HALF, _FIR_HALF + 1)
        taps = 2 * cutoff * np.sinc(2 * cutoff * n) * np.hamming(2 * _FIR_HALF + 1)
        samples = np.convolve(samples, taps / taps.sum(), mode="same")
    count = max(1, len(samples) * target // source)
    positions = np.arange(count) * (source / target)
    return np.interp(positions, np.arange(len(samples)), samples)


def decode_to_wav(data: bytes, *, sf: Any, np: Any) -> bytes:  # noqa: ANN401
    # Any: soundfile/numpy are optional, lazily imported (injected by tests as fakes).
    """Decode a checked voice note to a 16 kHz mono PCM16 WAV (<= 130 s).

    Raises:
        ValidationError: not Ogg/Opus (before decoding), odd stream, too long.
    """
    data = check_opus_input(data)
    info = sf.info(io.BytesIO(data))
    if info.format != "OGG" or info.subtype != "OPUS":
        raise ValidationError("voice is not Ogg/Opus")
    rate, channels = int(info.samplerate), int(info.channels)
    if not 1 <= channels <= _MAX_CHANNELS or not 8_000 <= rate <= _MAX_INPUT_RATE:
        raise ValidationError("voice has an unsupported layout")
    max_frames = rate * MAX_WAV_SECONDS
    # Read one frame more than allowed: a longer decode than the header said is refused.
    samples, _ = sf.read(io.BytesIO(data), frames=max_frames + 1, dtype="float32", always_2d=True)
    if len(samples) == 0 or len(samples) > max_frames:
        raise ValidationError("voice decodes to no audio or too much")
    mono = _resample(np, samples.mean(axis=1), rate, TARGET_RATE)[: MAX_WAV_SECONDS * TARGET_RATE]
    pcm = (np.clip(mono, -1.0, 1.0) * 32767.0).astype("<i2").tobytes()
    out = io.BytesIO()
    with wave.open(out, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(TARGET_RATE)
        wav.writeframes(pcm)
    return out.getvalue()


def _read_capped(path: str) -> bytes:
    with open(path, "rb") as fh:
        data = fh.read(VOICE_MAX_BYTES + 1)
    if len(data) > VOICE_MAX_BYTES:
        raise ValidationError("voice too large")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    """Decode `argv[0]` to a WAV on stdout; 0 on success, 3 on any refusal or failure."""
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(args) != 1:
            raise ValidationError("usage: voice_decode <ogg path>")
        data = check_opus_input(_read_capped(args[0]))  # before soundfile is even imported
        wav = decode_to_wav(
            data, sf=importlib.import_module("soundfile"), np=importlib.import_module("numpy")
        )
    except Exception:
        # Fixed text only: decoder errors may quote the input (C29).
        sys.stderr.write("voice decode refused\n")
        return EXIT_REFUSED
    sys.stdout.buffer.write(wav)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
