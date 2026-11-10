"""Sandboxed voice-note transcription (docs/security.md C62): pin check, sandbox argv, runner.

`verify_whisper_install` hash-checks `bin/whisper-cli` and
`models/ggml-base.bin` against the install's `whisper.sha256` at host
start (a mismatch turns voice input off; the caller alerts). Every step
that touches the audio runs under `systemd-run` with the S0 properties
(no network, dynamic user, read-only system, no home, private /tmp, no new
privileges, 2 GB / 120 s / 2 CPUs) plus a few kernel-facing extras, no
environment (`/usr/bin/env -i`), inputs bound read-only:
1. decode: `<venv python> -I -B -m …voice_decode /tmp/in.ogg` -> WAV on stdout;
2. whisper-cli `-m <model> -f /tmp/in.wav -l auto -t 2 -nt -np -mc 0` -> text.
The host writes the checked Ogg and the canonical WAV (re-checked here) to
a private 0700 job dir, deletes it in `finally`, and strips bracketed
non-speech tags from the output. Never logs audio or text.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import logging
import os
import re
import shutil
import stat
import subprocess  # nosec B404 - fixed argv list, no shell
import tempfile
import threading
import wave
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol

from preview_dashboard.adapters.voice_decode import (
    MAX_WAV_SECONDS,
    TARGET_RATE,
    WAV_MAX_BYTES,
    check_opus_input,
)
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.ports.claudia_media import TranscriptionError

_log = logging.getLogger(__name__)

DEFAULT_WHISPER_DIR: Final = Path("/opt/claudia-whisper")
PINS_NAME: Final = "whisper.sha256"
BINARY_REL: Final = "bin/whisper-cli"
MODEL_REL: Final = "models/ggml-base.bin"
# Pin lines written by install.sh --whisper: `<sha256>  binary`, `<sha256>  model`.
_PIN_LINE_RE = re.compile(r"([0-9a-f]{64})  (binary|model)")
_PINS_MAX_BYTES: Final = 4096
SYSTEMD_RUN: Final = Path("/usr/bin/systemd-run")
ENV_BIN: Final = "/usr/bin/env"
DECODE_MODULE: Final = "preview_dashboard.adapters.voice_decode"
SANDBOX_OGG: Final = "/tmp/in.ogg"  # noqa: S108  # nosec B108 - inside the unit's PrivateTmp
SANDBOX_WAV: Final = "/tmp/in.wav"  # noqa: S108  # nosec B108 - inside the unit's PrivateTmp
RUNTIME_MAX_SECONDS: Final = 120
# The host waits a little longer than systemd's own cap, then kills the client.
HOST_TIMEOUT_SECONDS: Final = RUNTIME_MAX_SECONDS + 15.0
TRANSCRIPT_MAX_BYTES: Final = 64 * 1024
WHISPER_ARGS: Final = ("-l", "auto", "-t", "2", "-nt", "-np", "-mc", "0")
# S0 (backlog 15.26): the set verified on this host, in this order.
S0_PROPERTIES: Final = (
    "PrivateNetwork=yes",
    "DynamicUser=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "NoNewPrivileges=yes",
    "MemoryMax=2G",
    f"RuntimeMaxSec={RUNTIME_MAX_SECONDS}",
    "CPUQuota=200%",
)
# Extras that never touch a CPU-only decoder: no devices, no core dumps with
# audio in them, no sockets but AF_UNIX, no namespaces, bounded tasks.
EXTRA_PROPERTIES: Final = (
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "RestrictAddressFamilies=AF_UNIX",
    "LimitCORE=0",
    "TasksMax=64",
)
# Bind paths go into one `-p` value: no ':' (the separator), spaces or escapes.
_BIND_PATH_RE = re.compile(r"/[A-Za-z0-9._/-]{1,255}")
# Non-speech tags whisper emits: `[MÚSICA]`, `[BLANK_AUDIO]`, `(music)`, `*laughs*`.
_TAG_RE = re.compile(r"\[[^\[\]\n]{0,80}\]|\([^()\n]{0,80}\)|\*[^*\n]{0,80}\*")
_JOB_PREFIX: Final = "voice-"


class WhisperPinError(RuntimeError):
    """The whisper install is missing, unsafe or does not match its pins (names a path only)."""


@dataclass(frozen=True, slots=True)
class WhisperInstall:
    """A verified install: the binary and model, both hash-checked at host start."""

    root: Path
    binary: Path
    model: Path


def _check_trusted(path: Path, st: os.stat_result, trusted_uids: Sequence[int]) -> None:
    if st.st_uid not in trusted_uids or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise WhisperPinError(f"{path} has an unsafe owner or mode")


def _regular(path: Path, trusted_uids: Sequence[int]) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise WhisperPinError(f"{path} is missing") from None
    if not stat.S_ISREG(st.st_mode):
        raise WhisperPinError(f"{path} is not a regular file")
    _check_trusted(path, st, trusted_uids)


def parse_pins(text: str) -> dict[str, str]:
    """`{"binary": hex, "model": hex}` from a pin file; `#` comment and blank lines ignored.

    Raises:
        WhisperPinError: any other line, a missing or repeated name.
    """
    pins: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = _PIN_LINE_RE.fullmatch(line)
        if match is None or match.group(2) in pins:
            raise WhisperPinError(f"{PINS_NAME} has an unexpected line")
        pins[match.group(2)] = match.group(1)
    if set(pins) != {"binary", "model"}:
        raise WhisperPinError(f"{PINS_NAME} must pin exactly the binary and the model")
    return pins


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise WhisperPinError(f"{path} can't be read") from None
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_whisper_install(root: Path, *, trusted_uids: Sequence[int] = (0,)) -> WhisperInstall:
    """Hash-check the install at host start (C62): trusted owner, pinned, unchanged.

    Raises:
        WhisperPinError: a missing/unsafe dir or file, a bad pin file, or a hash mismatch.
    """
    if not root.is_absolute():
        raise WhisperPinError("the whisper dir must be an absolute path")
    for directory in (root, root / "bin", root / "models"):
        try:
            st = os.lstat(directory)
        except OSError:
            raise WhisperPinError(f"{directory} is missing") from None
        if not stat.S_ISDIR(st.st_mode):
            raise WhisperPinError(f"{directory} is not a directory")
        _check_trusted(directory, st, trusted_uids)
    pins_path, binary, model = root / PINS_NAME, root / BINARY_REL, root / MODEL_REL
    for path in (pins_path, binary, model):
        _regular(path, trusted_uids)
    try:
        raw = pins_path.read_bytes()[: _PINS_MAX_BYTES + 1]
        text = raw.decode("ascii")
    except (OSError, UnicodeDecodeError):
        raise WhisperPinError(f"{pins_path} can't be read") from None
    if len(raw) > _PINS_MAX_BYTES:
        raise WhisperPinError(f"{pins_path} is too large")
    pins = parse_pins(text)
    for name, path in (("binary", binary), ("model", model)):
        if _sha256(path) != pins[name]:
            raise WhisperPinError(f"{path} does not match its pinned SHA-256")
    return WhisperInstall(root=root, binary=binary, model=model)


# --- the sandbox ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReadOnlyBind:
    """`BindReadOnlyPaths=<source>:<target>`; both plain absolute paths.

    Raises (constructor):
        ValueError: a path with `:`, spaces, `..`, `//` or other odd characters.
    """

    source: str
    target: str

    def __post_init__(self) -> None:
        for path in (self.source, self.target):
            if not _BIND_PATH_RE.fullmatch(path) or "/../" in f"{path}/" or "//" in path:
                raise ValueError("unsafe bind path")

    @property
    def prop(self) -> str:
        """The `-p` value."""
        return f"BindReadOnlyPaths={self.source}:{self.target}"


def sandbox_argv(
    command: Sequence[str],
    binds: Sequence[ReadOnlyBind],
    *,
    systemd_run: Path = SYSTEMD_RUN,
) -> list[str]:
    """`systemd-run` argv running `command` in the C62 sandbox; no env reaches it.

    `command[0]` must be absolute: systemd resolves the exec path on the
    host, so it runs through `/usr/bin/env -i` (S0), which also clears the
    service manager's default environment. No `--setenv`/`-E` is ever added.

    Raises:
        ValueError: an empty or relative command.
    """
    if not command or not command[0].startswith("/"):
        raise ValueError("the sandboxed command must be an absolute path")
    argv = [str(systemd_run), "--wait", "--pipe", "--collect", "--quiet"]
    for prop in (*S0_PROPERTIES, *EXTRA_PROPERTIES, *(bind.prop for bind in binds)):
        argv += ["-p", prop]
    return [*argv, ENV_BIN, "-i", *command]


def decode_argv(python: Path, job_ogg: Path) -> list[str]:
    """The decode step: the venv Python, isolated (`-I -B`), on the read-only bound Ogg."""
    command = [str(python), "-I", "-B", "-m", DECODE_MODULE, SANDBOX_OGG]
    return sandbox_argv(command, [ReadOnlyBind(str(job_ogg), SANDBOX_OGG)])


def whisper_argv(install: WhisperInstall, job_wav: Path) -> list[str]:
    """The transcription step: whisper-cli on the read-only bound WAV and model."""
    model = str(install.model)
    command = [str(install.binary), "-m", model, "-f", SANDBOX_WAV, *WHISPER_ARGS]
    binds = [ReadOnlyBind(str(job_wav), SANDBOX_WAV), ReadOnlyBind(model, model)]
    return sandbox_argv(command, binds)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """One sandbox run: exit code (None = killed or not started), capped stdout, why it stopped."""

    exit_code: int | None
    stdout: bytes = field(default=b"", repr=False)
    timed_out: bool = False
    overflow: bool = False


class SandboxExec(Protocol):
    """Runs one sandbox argv (tests fake it; never a real `systemd-run` in tests)."""

    def run(self, argv: Sequence[str], *, max_output: int, timeout: float) -> SandboxResult:
        """Run `argv` with an empty env and no stdin; stdout capped at `max_output` bytes."""
        ...


class SubprocessSandboxExec:
    """`SandboxExec` over `subprocess` (stderr dropped: it may echo content)."""

    def run(self, argv: Sequence[str], *, max_output: int, timeout: float) -> SandboxResult:
        """See `SandboxExec.run`; a spawn failure is a failed result, never an exception."""
        try:
            proc = subprocess.Popen(  # noqa: S603  # nosec B603 - fixed argv, no shell
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={},  # C62: nothing of the host's environment
                close_fds=True,
            )
        except OSError as exc:
            _log.error("sandbox could not start (%s)", type(exc).__name__)
            return SandboxResult(exit_code=None)
        expired = threading.Event()

        def _expire() -> None:
            expired.set()
            proc.kill()

        timer = threading.Timer(timeout, _expire)
        timer.start()
        out = bytearray()
        overflow = False
        try:
            stream = proc.stdout
            while stream is not None:
                chunk = os.read(stream.fileno(), 65536)  # returns as soon as data arrives
                if not chunk:
                    break
                out += chunk
                if len(out) > max_output:
                    overflow = True
                    proc.kill()
                    break
            try:
                proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                proc.kill()
        finally:
            timer.cancel()
            if proc.stdout is not None:
                proc.stdout.close()
        if expired.is_set() or overflow:
            return SandboxResult(exit_code=None, timed_out=expired.is_set(), overflow=overflow)
        return SandboxResult(exit_code=proc.returncode, stdout=bytes(out))


def check_pcm16_wav(data: bytes) -> None:
    """The decode output must be a canonical 16 kHz mono PCM16 WAV of <= 130 s.

    whisper-cli only ever reads such a host-checked file (its own audio
    parsers are not trusted, S0).

    Raises:
        ValidationError: anything else.
    """
    if not 44 < len(data) <= WAV_MAX_BYTES or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValidationError("decoded audio is not a WAV")
    try:
        with wave.open(io.BytesIO(data), "rb") as wav:
            ok = (
                wav.getnchannels() == 1
                and wav.getsampwidth() == 2
                and wav.getframerate() == TARGET_RATE
                and wav.getcomptype() == "NONE"
                and 0 < wav.getnframes() <= MAX_WAV_SECONDS * TARGET_RATE
            )
    except (wave.Error, EOFError):
        raise ValidationError("decoded audio is not a WAV") from None
    if not ok:
        raise ValidationError("decoded audio is not 16 kHz mono PCM16 within 130 s")


def strip_non_speech(text: str) -> str:
    """Drop bracketed non-speech tags (`[MÚSICA]`, `(music)`, `*laughs*`) and blank lines."""
    lines = (" ".join(_TAG_RE.sub(" ", line).split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def prepare_scratch(root: Path) -> Path:
    """The host's private scratch dir (created 0700 if missing); leftover jobs are removed.

    Raises:
        WhisperPinError: a symlink, a foreign owner or a mode wider than 0700.
    """
    with contextlib.suppress(FileExistsError):
        root.mkdir(mode=0o700)
    st = os.lstat(root)
    if (
        not stat.S_ISDIR(st.st_mode)
        or st.st_uid != os.geteuid()
        or stat.S_IMODE(st.st_mode) & 0o077
    ):
        raise WhisperPinError(f"{root} has an unsafe owner or mode")
    for entry in os.listdir(root):
        if entry.startswith(_JOB_PREFIX):
            shutil.rmtree(root / entry, ignore_errors=True)  # a crash mid-job
    return root


def _write(path: Path, data: bytes) -> None:
    # 0644: the sandbox's dynamic user reads it only through the bind; the
    # 0700 job and scratch dirs keep every other local user out.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o644)
        fh.write(data)


class SandboxTranscriber:
    """`Transcriber`: decode + whisper-cli, each in its own sandbox run (C62).

    Args:
        install: the verified whisper install (`verify_whisper_install`).
        python: the venv interpreter that runs the decode module.
        scratch: the host's private 0700 scratch dir (`prepare_scratch`).
        sandbox: runs the argv (default: `systemd-run` through `subprocess`).
    """

    def __init__(
        self,
        install: WhisperInstall,
        *,
        python: Path,
        scratch: Path,
        sandbox: SandboxExec | None = None,
    ) -> None:
        if not python.is_absolute() or not scratch.is_absolute():
            raise ValueError("python and scratch must be absolute paths")
        self._install = install
        self._python = python
        self._scratch = scratch
        self._sandbox = sandbox or SubprocessSandboxExec()

    def transcribe(self, audio: bytes) -> str:
        """See `Transcriber.transcribe`; the job dir is gone when this returns or raises."""
        try:
            check_opus_input(audio)  # never hand anything else to a decoder
        except ValidationError:
            raise TranscriptionError("voice note refused: not Ogg/Opus") from None
        job = Path(tempfile.mkdtemp(prefix=_JOB_PREFIX, dir=self._scratch))
        try:
            ogg, wav = job / "in.ogg", job / "in.wav"
            _write(ogg, audio)
            decoded = self._step(decode_argv(self._python, ogg), WAV_MAX_BYTES, "decode")
            try:
                check_pcm16_wav(decoded)
            except ValidationError:
                raise TranscriptionError("voice note decode gave no valid WAV") from None
            _write(wav, decoded)
            ogg.unlink()  # whisper never sees the Ogg
            raw = self._step(whisper_argv(self._install, wav), TRANSCRIPT_MAX_BYTES, "whisper")
        finally:
            shutil.rmtree(job, ignore_errors=True)
        text = strip_non_speech(raw.decode("utf-8", "replace"))
        if not text:
            raise TranscriptionError("voice note had no speech")
        return text

    def _step(self, argv: Sequence[str], cap: int, name: str) -> bytes:
        result = self._sandbox.run(argv, max_output=cap, timeout=HOST_TIMEOUT_SECONDS)
        if result.timed_out:
            raise TranscriptionError(f"voice note {name} timed out")
        if result.exit_code != 0 or result.overflow:
            raise TranscriptionError(f"voice note {name} failed")
        return result.stdout
