"""Security tests for the TOTP step-up (unit M3): C47.

RFC 4226 / RFC 6238 vectors, the ±1 step window, no replay, constant-time
comparison, lockout (5 wrong in 15 min -> 15 min) persisted across
restarts, the wrong-code alert, fail-closed secret and state files, the
secret never in responses or logs, and `claudia totp setup` (root + TTY
only, no overwrite without `--rotate`, one valid code before writing, that
code's step burnt first so it can never approve: unit A1). F-C1b: exact
`(update_id, message_id)` re-delivery guard, the admin-only `pdash-totp`
group (never the shared primary group) at load, serve-admin and setup.
"""

from __future__ import annotations

import contextlib
import grp
import hmac
import io
import json
import logging
import os
import stat
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from starlette.testclient import TestClient

from preview_dashboard.adapters.stepup_state import (
    STATE_FILE_NAME,
    FileStepUpState,
    StepUpStateError,
)
from preview_dashboard.adapters.totp_secret import (
    FileTotpSecret,
    TotpSecretFileError,
    load_totp_secret,
    write_totp_secret,
)
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.totp import (
    LOCKOUT_SECONDS,
    SEEN_CODES_MAX,
    SEEN_CODES_SECONDS,
    SeenCode,
    StepUpState,
    TotpError,
    decode_secret,
    encode_secret,
    hotp,
    matching_step,
    otpauth_uri,
    parse_code,
    time_step,
    totp_at,
)
from preview_dashboard.interfaces.cli import (
    CliError,
    TerminalIO,
    token_groups,
    totp_groups,
    totp_setup,
)
from preview_dashboard.interfaces.token_file import TokenGroupPolicy, TokenKind
from tests.claudia_admin_support import (
    TEST_SECRET,
    approval_body,
    claudia_app,
    code_body,
    tap_body,
)
from tests.notify_admin_support import bearer

pytestmark = pytest.mark.security

RFC_SECRET = b"12345678901234567890"
# Fullwidth digits (Unicode Nd but not ASCII): must never parse as a code.
FULLWIDTH_CODE = "".join(chr(0xFF10 + int(d)) for d in "123456")


# --- RFC vectors ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("counter", "expected"),
    list(
        enumerate(
            [
                "755224",
                "287082",
                "359152",
                "969429",
                "338314",
                "254676",
                "287922",
                "162583",
                "399871",
                "520489",
            ]
        )
    ),
)
def test_c47_rfc4226_hotp_vectors(counter, expected):
    assert hotp(RFC_SECRET, counter) == expected


@pytest.mark.parametrize(
    ("unix", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_c47_rfc6238_sha1_vectors(unix, expected):
    assert totp_at(RFC_SECRET, unix, digits=8) == expected
    assert totp_at(RFC_SECRET, unix) == expected[-6:]


def test_c47_time_step_edges():
    assert (time_step(0), time_step(29.999), time_step(30), time_step(59)) == (0, 0, 1, 1)
    with pytest.raises(TotpError):
        time_step(-1)


# --- window, replay, constant time --------------------------------------------------------


NOW = 1_800_000_015  # mid-step


@pytest.mark.parametrize(
    ("offset", "accepted"), [(-2, False), (-1, True), (0, True), (1, True), (2, False)]
)
def test_c47_window_is_minus_one_to_plus_one(offset, accepted):
    code = totp_at(TEST_SECRET, NOW + 30 * offset)
    step = matching_step(TEST_SECRET, code, time_step(NOW), after_step=None)
    assert (step == time_step(NOW) + offset) if accepted else step is None


def test_c47_no_replay_of_the_same_or_an_older_step():
    now_step = time_step(NOW)
    current = totp_at(TEST_SECRET, NOW)
    older = totp_at(TEST_SECRET, NOW - 30)
    assert matching_step(TEST_SECRET, current, now_step, after_step=now_step) is None
    assert matching_step(TEST_SECRET, older, now_step, after_step=now_step - 1) is None
    assert matching_step(TEST_SECRET, current, now_step, after_step=now_step - 1) == now_step


def test_c47_every_candidate_is_compared_in_constant_time(monkeypatch):
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return bool(real(a, b))

    # domain.totp calls `hmac.compare_digest` through the module: patch it there.
    monkeypatch.setattr(hmac, "compare_digest", spy)
    # The first candidate (step -1) matches; the other two are still compared.
    code = totp_at(TEST_SECRET, NOW - 30)
    assert matching_step(TEST_SECRET, code, time_step(NOW), after_step=None) is not None
    assert len(calls) == 3


@pytest.mark.parametrize(
    "raw", ["12345", "1234567", "12 3456", " 123456", FULLWIDTH_CODE, "١٢٣٤٥٦", 123456, None]
)
def test_c47_code_syntax_is_exactly_six_ascii_digits(raw):
    with pytest.raises(ValidationError):
        parse_code(raw)


def test_c47_secret_encoding_is_strict():
    text = encode_secret(TEST_SECRET)
    assert decode_secret(text) == TEST_SECRET
    for bad in (text.lower(), text + "=", text[:-8], f" {text}", "A" * 31 + "1"):
        with pytest.raises(TotpError):
            decode_secret(bad)
    with pytest.raises(TotpError):
        encode_secret(b"short")  # < 160 bits


def test_c47_otpauth_uri():
    uri = otpauth_uri(TEST_SECRET, issuer="Preview Dashboard", account="Claudia")
    assert uri == (
        "otpauth://totp/Preview%20Dashboard:Claudia?secret="
        f"{encode_secret(TEST_SECRET)}&issuer=Preview%20Dashboard&algorithm=SHA1&digits=6&period=30"
    )
    with pytest.raises(TotpError):
        otpauth_uri(TEST_SECRET, issuer="x&secret=evil", account="Claudia")


# --- lockout rules + persisted state --------------------------------------------------------


def test_c47_five_wrong_codes_in_15_minutes_lock_for_15_minutes():
    state = StepUpState()
    for i in range(4):
        state = state.with_failure(1000 + i)
        assert not state.is_locked(1000 + i)
    state = state.with_failure(1004)
    assert state.is_locked(1004)
    assert state.is_locked(1004 + LOCKOUT_SECONDS - 1)
    assert not state.is_locked(1004 + LOCKOUT_SECONDS)


def test_c47_old_failures_fall_out_of_the_window():
    state = StepUpState()
    for t in (0, 1, 2, 3):
        state = state.with_failure(t)
    state = state.with_failure(15 * 60 + 5)  # the first four are older than 15 min
    assert not state.is_locked(15 * 60 + 5)
    assert state.failures == (15 * 60 + 5,)


def test_c47_success_cannot_move_the_replay_mark_back():
    state = StepUpState().with_success(10)
    with pytest.raises(TotpError):
        state.with_success(10)
    assert state.with_success(11).last_step == 11


def test_c47_state_file_round_trip_and_mode(tmp_path):
    data = _data_dir(tmp_path)
    store = FileStepUpState(data)
    assert store.load() == StepUpState()
    state = StepUpState(
        last_step=5, failures=(1, 2), locked_until=None, seen=(SeenCode(9, 88, 1000),)
    )
    store.save(state)
    assert FileStepUpState(data).load() == state  # a new instance = a restart
    assert stat.S_IMODE(os.stat(data / STATE_FILE_NAME).st_mode) == 0o600


def test_c47_version_1_state_file_keeps_replay_mark_and_lockout(tmp_path):
    # M3's file had an update-id high-water mark; it is dropped, nothing else is.
    data = _data_dir(tmp_path)
    path = data / STATE_FILE_NAME
    old = {"version": 1, "last_step": 7, "failures": [3], "locked_until": 99, "last_update_id": 5}
    path.write_text(json.dumps(old))
    os.chmod(path, 0o600)
    assert FileStepUpState(data).load() == StepUpState(last_step=7, failures=(3,), locked_until=99)


def test_c47_seen_code_messages_are_exact_pairs_bounded_to_32_and_24h():
    state = StepUpState().with_seen_code(50, 7, 1000)
    assert state.is_seen_code(50, 7, 1000)
    # A lower update id (Telegram may restart its numbering) is a new message.
    assert not state.is_seen_code(49, 8, 1000)
    assert not state.is_seen_code(50, 8, 1000)  # same update id, other message
    assert not state.is_seen_code(50, 7, 1000 + SEEN_CODES_SECONDS)  # older than 24 h
    for i in range(SEEN_CODES_MAX + 5):
        state = state.with_seen_code(100 + i, 200 + i, 2000 + i)
    assert len(state.seen) == SEEN_CODES_MAX
    assert not state.is_seen_code(100, 200, 2100)  # the oldest fell out
    assert state.is_seen_code(100 + SEEN_CODES_MAX + 4, 200 + SEEN_CODES_MAX + 4, 2100)
    with pytest.raises(TotpError):
        StepUpState(seen=(SeenCode(1, 1, 1),) * 2)
    with pytest.raises(TotpError):
        SeenCode(-1, 1, 1)


@pytest.mark.parametrize("tamper", ["mode", "json", "shape", "symlink", "hardlink"])
def test_c47_untrusted_state_fails_closed(tmp_path, tamper):
    data = _data_dir(tmp_path)
    store = FileStepUpState(data)
    store.save(StepUpState(locked_until=10**9))
    path = data / STATE_FILE_NAME
    if tamper == "mode":
        os.chmod(path, 0o644)
    elif tamper == "json":
        path.write_text("{not json")
    elif tamper == "shape":
        path.write_text(json.dumps({"version": 1, "last_step": None}))
    elif tamper == "symlink":
        target = tmp_path / "elsewhere.json"
        os.replace(path, target)
        path.symlink_to(target)
    else:
        os.link(path, tmp_path / "second-link")
    with pytest.raises(StepUpStateError):
        store.load()


def _data_dir(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir(mode=0o750)
    return data


# --- secret file -------------------------------------------------------------------------


def _load(path: Path, **kw: Any) -> bytes:
    # Test files carry this process's group; production trusts `pdash-totp` instead.
    return load_totp_secret(path, trusted_gids=(os.getegid(),), **kw)


def test_c47_secret_file_rules(tmp_path):
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    path = secrets_dir / "totp.secret"
    write_totp_secret(path, TEST_SECRET, gid=None, replace=False)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert _load(path) == TEST_SECRET
    with pytest.raises(FileExistsError):
        write_totp_secret(path, TEST_SECRET, gid=None, replace=False)
    for mode in (0o644, 0o660, 0o604):
        os.chmod(path, mode)
        with pytest.raises(TotpSecretFileError):
            _load(path)
    os.chmod(path, 0o600)
    with pytest.raises(TotpSecretFileError, match="owner"):
        _load(path, trusted_uids={os.geteuid() + 12345})
    link = secrets_dir / "link.secret"
    link.symlink_to(path)
    with pytest.raises(TotpSecretFileError):
        _load(link)
    path.write_text("not base32!\n")
    with pytest.raises(TotpSecretFileError) as caught:
        _load(path)
    assert "base32!" not in str(caught.value)  # never echoes content
    os.chmod(secrets_dir, 0o777)  # noqa: S103 - the point: an untrusted directory
    path.write_text(encode_secret(TEST_SECRET) + "\n")
    with pytest.raises(TotpSecretFileError, match="directory"):
        _load(path)
    os.chmod(secrets_dir, 0o700)


def test_c47_secret_in_the_shared_primary_group_is_refused(tmp_path, monkeypatch):
    # S-C1 S2: the admin's primary group `pdash` is shared with the viewer; a
    # `root:pdash` secret would be viewer-readable, so this process's own group
    # is never trusted implicitly (unlike token files) - only `pdash-totp`.
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    path = secrets_dir / "totp.secret"
    write_totp_secret(path, TEST_SECRET, gid=None, replace=False)
    shared = os.stat(path).st_gid
    if shared == 0:
        # Root runs: give the file a non-root group and make it "our" group.
        shared = _other_gid()
        os.chown(path, -1, shared)
        monkeypatch.setattr(os, "getegid", lambda: shared)
    with pytest.raises(TotpSecretFileError, match="group"):
        load_totp_secret(path)
    with pytest.raises(TotpSecretFileError, match="group"):
        FileTotpSecret(path).load()
    # 0640 + a group the viewer is not in: the viewer has no read bit at all.
    assert not stat.S_IMODE(os.stat(path).st_mode) & stat.S_IRWXO
    assert FileTotpSecret(path, trusted_gids=(shared,)).load() == TEST_SECRET


def _other_gid() -> int:
    """A real non-root group (root may chown to it); else this process's group."""
    if os.geteuid() != 0:
        return os.getegid()
    return next(g.gr_gid for g in grp.getgrall() if g.gr_gid != 0)


def test_c47_written_secret_must_carry_the_requested_group(tmp_path):
    if os.geteuid() != 0:
        pytest.skip("needs root to make a setgid directory of another group")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir(mode=0o700)
    os.chown(secrets_dir, -1, _other_gid())
    os.chmod(secrets_dir, 0o2700)  # setgid: new files inherit the directory's group
    path = secrets_dir / "totp.secret"
    with pytest.raises(TotpSecretFileError, match="group"):
        write_totp_secret(path, TEST_SECRET, gid=None, replace=False)
    assert not path.exists()


def test_c47_serve_admin_totp_group_must_be_its_own():
    other = _other_gid()
    away = other + 1  # a primary gid that is not `other`
    # Root, the primary group (pdash), a plain or a scoped token group: all refused.
    refused = [
        (["totp=0"], TokenGroupPolicy(own=TokenKind.ADMIN, egid=away)),
        ([f"totp={other}"], TokenGroupPolicy(own=TokenKind.ADMIN, egid=other)),
        (
            [f"totp={other}"],
            TokenGroupPolicy(own=TokenKind.ADMIN, shared=frozenset({other}), egid=away),
        ),
        (
            [f"totp={other}"],
            TokenGroupPolicy(
                own=TokenKind.ADMIN, scoped={TokenKind.NOTIFIER: frozenset({other})}, egid=away
            ),
        ),
    ]
    for values, policy in refused:
        with pytest.raises(CliError, match="own group"):
            totp_groups(values, tokens=policy)
    accepted = TokenGroupPolicy(own=TokenKind.ADMIN, egid=away)
    assert totp_groups([f"totp={other}", "admin=0"], tokens=accepted) == {other}
    # `totp=` is not a token kind: the token policy ignores it.
    assert token_groups([f"totp={other}"], own=TokenKind.ADMIN).gids_for(TokenKind.NOTIFIER) == {0}


# --- service through the routes --------------------------------------------------------------


def _tapped(client: TestClient, rig: Any, window: str | None = None) -> str:
    body = approval_body() if window is None else approval_body(window_id=window)
    created = client.post("/v1/claudia/approvals", json=body, headers=bearer(rig.claudia_token))
    assert created.status_code == 201, created.text
    aid: str = created.json()["approval"]["id"]
    tapped = client.post(
        "/v1/notifier/approvals", json=tap_body(aid), headers=bearer(rig.notifier_token)
    )
    assert tapped.json() == {"result": "tapped"}
    return aid


def _code(client: TestClient, rig: Any, code: str, update_id: int, message_id: int = 5) -> str:
    response = client.post(
        "/v1/notifier/codes",
        json=code_body(code, update_id, message_id=message_id),
        headers=bearer(rig.notifier_token),
    )
    assert response.status_code == 200, response.text
    result: str = response.json()["result"]
    return result


def _state(client: TestClient, rig: Any, aid: str) -> str:
    got = client.get(f"/v1/claudia/approvals/{aid}", headers=bearer(rig.claudia_token))
    state: str = got.json()["approval"]["state"]
    return state


def _wrong(code: str) -> str:
    return f"{(int(code) + 1) % 1_000_000:06d}"


def test_c47_valid_code_approves_the_tapped_request(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _tapped(client, rig)
        assert _code(client, rig, rig.code(), 1) == "accepted"
        assert _state(client, rig, aid) == "approved"


def test_c47_code_replay_is_refused(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        code = rig.code()
        first = _tapped(client, rig)
        assert _code(client, rig, code, 1) == "accepted"
        consumed = client.post(
            f"/v1/claudia/approvals/{first}/consume", headers=bearer(rig.claudia_token)
        )
        assert consumed.json()["result"] == "consumed"
        second = _tapped(client, rig)
        assert _code(client, rig, code, 2) == "refused"  # same step again
        assert _code(client, rig, rig.code(-1), 3) == "refused"  # an older step
        assert _state(client, rig, second) == "tapped"
        rig.clock.advance(timedelta(seconds=30))
        assert _code(client, rig, rig.code(), 4) == "accepted"  # the next step is fine


def test_c47_redelivered_code_update_is_not_counted(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        _tapped(client, rig)
        wrong = _wrong(rig.code())
        assert _code(client, rig, wrong, 50, 70) == "refused"
        for _ in range(6):
            assert _code(client, rig, wrong, 50, 70) == "duplicate"  # same message again
        assert _code(client, rig, rig.code(), 51, 71) == "accepted"  # never locked


def test_c47_code_with_a_decreasing_update_id_is_still_checked(tmp_path):
    # S-C1 S0: Telegram may restart update ids lower; a high-water mark would
    # have answered "duplicate" to every fresh code (an approval DoS).
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        first = _tapped(client, rig)
        assert _code(client, rig, _wrong(rig.code()), 900, 70) == "refused"
        assert _code(client, rig, rig.code(), 3, 71) == "accepted"  # lower update id
        consumed = client.post(
            f"/v1/claudia/approvals/{first}/consume", headers=bearer(rig.claudia_token)
        )
        assert consumed.json()["result"] == "consumed"
        second = _tapped(client, rig)
        # A replay of that code (same step, yet another new message) is still refused.
        assert _code(client, rig, rig.code(), 2, 72) == "refused"
        assert _state(client, rig, second) == "tapped"


def test_c47_code_without_tapped_request_counts_as_wrong(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        for update in range(1, 5):
            assert _code(client, rig, rig.code(), update) == "refused"
        assert _code(client, rig, rig.code(), 5) == "locked"  # 5th wrong


def test_c47_lockout_persists_across_restarts(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        _tapped(client, rig)
        wrong = _wrong(rig.code())
        results = [_code(client, rig, wrong, u) for u in range(1, 6)]
        assert results == ["refused"] * 4 + ["locked"]
        assert _code(client, rig, rig.code(), 6) == "locked"  # even the right code
    # Same data dir, new core: still locked.
    with claudia_app(tmp_path, write_secret=False) as rig, TestClient(rig.app) as client:
        assert _code(client, rig, rig.code(), 7) == "locked"
        rig.clock.advance(timedelta(seconds=LOCKOUT_SECONDS))
        # The old request expired meanwhile; a fresh one can be approved again.
        aid = _tapped(client, rig, window="223e4567-e89b-42d3-a456-426614174000")
        assert _code(client, rig, rig.code(), 8) == "accepted"
        assert _state(client, rig, aid) == "approved"


def test_c47_each_wrong_code_raises_one_alert_without_the_code(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        _tapped(client, rig)
        before = len(rig.core.outbox.pending(20))
        wrong = _wrong(rig.code())
        assert _code(client, rig, wrong, 1) == "refused"
        assert _code(client, rig, wrong, 2) == "refused"
        tasks = rig.core.outbox.pending(20)[before:]
        assert len(tasks) == 2
        for task in tasks:
            assert "Wrong authenticator code" in task.payload.content.text
            assert wrong not in task.payload.content.text


def test_c47_alert_budget_exhaustion_does_not_break_checking(tmp_path):
    with claudia_app(tmp_path, notify_rate_per_hour=1) as rig, TestClient(rig.app) as client:
        aid = _tapped(client, rig)
        wrong = _wrong(rig.code())
        assert [_code(client, rig, wrong, u) for u in (1, 2)] == ["refused", "refused"]
        assert _code(client, rig, rig.code(), 3) == "accepted"
        assert _state(client, rig, aid) == "approved"


@pytest.mark.parametrize("problem", ["missing", "mode", "garbage"])
def test_c47_bad_secret_file_refuses_every_code(tmp_path, problem):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _tapped(client, rig)
        if problem == "missing":
            rig.secret_path.unlink()
        elif problem == "mode":
            os.chmod(rig.secret_path, 0o644)
        else:
            rig.secret_path.write_text("garbage\n")
        assert _code(client, rig, rig.code(), 1) == "refused"
        assert _state(client, rig, aid) == "tapped"


def test_c47_code_from_another_sender_is_refused(tmp_path):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _tapped(client, rig)
        response = client.post(
            "/v1/notifier/codes",
            json=code_body(rig.code(), 1, sender_id=999),
            headers=bearer(rig.notifier_token),
        )
        assert response.json() == {"result": "refused"}
        assert _state(client, rig, aid) == "tapped"


@pytest.mark.parametrize("code", ["12345", "1234567", FULLWIDTH_CODE, "12 456"])
def test_c47_malformed_code_is_a_400_not_a_try(tmp_path, code):
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        response = client.post(
            "/v1/notifier/codes", json=code_body(code), headers=bearer(rig.notifier_token)
        )
        assert response.status_code == 400
        assert code not in response.text


def test_c47_secret_and_code_never_in_responses_or_logs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    encoded = encode_secret(TEST_SECRET)
    with claudia_app(tmp_path) as rig, TestClient(rig.app) as client:
        aid = _tapped(client, rig)
        code = rig.code()
        bodies = [
            client.post(
                "/v1/notifier/codes",
                json=code_body(_wrong(code), 1),
                headers=bearer(rig.notifier_token),
            ).text,
            client.post(
                "/v1/notifier/codes", json=code_body(code, 2), headers=bearer(rig.notifier_token)
            ).text,
            client.get(f"/v1/claudia/approvals/{aid}", headers=bearer(rig.claudia_token)).text,
        ]
    for text in (*bodies, caplog.text):
        assert encoded not in text
        assert code not in text
        assert _wrong(code) not in text


# --- `claudia totp setup` ------------------------------------------------------------------


class _Term:
    def __init__(self, codes: list[str], *, tty: bool = True, root: bool = True) -> None:
        self.out = io.StringIO()
        self.codes = codes
        self.tty = tty
        self.root = root
        self.secret: bytes | None = None
        self.now: float = NOW

    def io(self, now: float = NOW) -> TerminalIO:
        self.now = now
        return TerminalIO(
            out=self.out,
            stdin_isatty=lambda: self.tty,
            stdout_isatty=lambda: self.tty,
            read_code=self._read,
            is_root=lambda: self.root,
            now=lambda: now,
        )

    def _read(self, prompt: str) -> str:
        # Compute the right code from the URI printed so far (like a phone would).
        if self.codes and self.codes[0] == "VALID":
            self.codes.pop(0)
            return totp_at(self._printed_secret(), self.now)
        return self.codes.pop(0)

    def _printed_secret(self) -> bytes:
        line = next(x for x in self.out.getvalue().splitlines() if "manual key:" in x)
        return decode_secret(line.split("manual key:")[1].strip())


def _setup_state(tmp_path: Path) -> FileStepUpState:
    data = tmp_path / "data"
    data.mkdir(mode=0o700, exist_ok=True)
    return FileStepUpState(data)


ADMIN_NAME = "pdash-admin"


class _Groups:
    """Fake `GroupDb`: the admin's primary group is elsewhere; `members` for every gid."""

    def __init__(self, members: frozenset[str] = frozenset({ADMIN_NAME}), primary: int = -1):
        self._members = members
        self._primary = primary

    def user_name(self, uid: int) -> str:
        return ADMIN_NAME

    def primary_gid(self, uid: int) -> int:
        return self._primary

    def members(self, gid: int) -> frozenset[str]:
        return self._members


_GROUP = object()  # "use the default test group"


def _setup(
    path: Path,
    term: _Term,
    tmp_path: Path,
    *,
    rotate: bool = False,
    group: object = _GROUP,
    groups: _Groups | None = None,
    **kw: Any,
) -> int:
    state = kw.pop("state", None) or _setup_state(tmp_path)
    return totp_setup(
        path,
        term.io(**kw),
        rotate=rotate,
        group=str(_other_gid()) if group is _GROUP else cast("str | None", group),
        state=state,
        admin_uid=os.geteuid(),
        groups=groups or _Groups(),
    )


def _load_setup(path: Path) -> bytes:
    return load_totp_secret(path, trusted_gids=(_other_gid(),))


def test_c47_setup_writes_secret_after_one_valid_code(tmp_path):
    path = tmp_path / "totp.secret"
    term = _Term(["000000", "VALID"])
    assert _setup(path, term, tmp_path) == 0
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640
    assert os.stat(path).st_gid == _other_gid()
    assert _load_setup(path) == term._printed_secret()
    assert term.out.getvalue().count("otpauth://totp/") == 1


@pytest.mark.parametrize(
    ("group", "groups", "match"),
    [
        (None, None, "--group is required"),
        ("0", None, "root or the admin's primary group"),
        (_GROUP, _Groups(primary=_other_gid()), "root or the admin's primary group"),
        (_GROUP, _Groups(members=frozenset({"someone"})), "not in group"),
        (_GROUP, _Groups(members=frozenset({ADMIN_NAME, "pdash-viewer"})), "other members"),
    ],
)
def test_c47_setup_refuses_a_missing_or_shared_group(tmp_path, group, groups, match):
    # S-C1 S2/S6: the secret's group must be the admin's alone, checked before any secret shows.
    path = tmp_path / "totp.secret"
    term = _Term(["VALID"])
    with pytest.raises(CliError, match=match):
        _setup(path, term, tmp_path, group=group, groups=groups)
    assert not path.exists()
    assert "otpauth" not in term.out.getvalue()


def test_c47_setup_rotate_keeps_the_current_group_and_vets_it(tmp_path):
    path = tmp_path / "totp.secret"
    write_totp_secret(path, TEST_SECRET, gid=_other_gid(), replace=False)
    term = _Term(["VALID"])
    assert _setup(path, term, tmp_path, rotate=True, group=None) == 0
    assert os.stat(path).st_gid == _other_gid()
    assert _load_setup(path) == term._printed_secret()
    # A file still in the shared group is not kept: rotate then needs --group.
    with pytest.raises(CliError, match="primary group"):
        _setup(
            path,
            _Term(["VALID"]),
            tmp_path,
            rotate=True,
            group=None,
            groups=_Groups(primary=_other_gid()),
        )


@pytest.mark.parametrize(("tty", "root"), [(False, True), (True, False)])
def test_c47_setup_refuses_non_tty_or_non_root(tmp_path, tty, root):
    path = tmp_path / "totp.secret"
    term = _Term(["VALID"], tty=tty, root=root)
    with pytest.raises(CliError):
        _setup(path, term, tmp_path)
    assert not path.exists()
    assert "otpauth" not in term.out.getvalue()  # nothing shown either


def test_c47_setup_refuses_overwrite_without_rotate(tmp_path):
    path = tmp_path / "totp.secret"
    write_totp_secret(path, TEST_SECRET, gid=_other_gid(), replace=False)
    with pytest.raises(CliError, match="--rotate"):
        _setup(path, _Term(["VALID"]), tmp_path)
    assert _load_setup(path) == TEST_SECRET
    term = _Term(["VALID"])
    assert _setup(path, term, tmp_path, rotate=True) == 0
    assert _load_setup(path) == term._printed_secret() != TEST_SECRET
    with pytest.raises(CliError, match="nothing to rotate"):
        _setup(tmp_path / "absent.secret", _Term(["VALID"]), tmp_path, rotate=True)


def test_c47_setup_writes_nothing_without_a_valid_code(tmp_path):
    path = tmp_path / "totp.secret"
    with pytest.raises(CliError, match="no valid code"):
        _setup(path, _Term(["111111", "abc", "222222"]), tmp_path)
    assert not path.exists()
    assert not (tmp_path / "data" / STATE_FILE_NAME).exists()  # nothing burnt either


def test_c47_setup_burns_the_accepted_step(tmp_path):
    state = _setup_state(tmp_path)
    seen = (SeenCode(9, 8, int(NOW) - 60),)
    state.save(StepUpState(failures=(int(NOW) - 60,), seen=seen))
    assert _setup(tmp_path / "totp.secret", _Term(["VALID"]), tmp_path, state=state) == 0
    # The replay mark moved to the setup's step; counters were not reset by setup.
    assert state.load() == StepUpState(
        last_step=time_step(NOW), failures=(int(NOW) - 60,), seen=seen
    )


def test_c47_setup_burn_never_moves_the_replay_mark_back(tmp_path):
    state = _setup_state(tmp_path)
    later = time_step(NOW) + 5
    state.save(StepUpState(last_step=later))
    assert _setup(tmp_path / "totp.secret", _Term(["VALID"]), tmp_path, state=state) == 0
    assert state.load().last_step == later


def test_c47_setup_writes_nothing_if_the_step_cannot_be_burnt(tmp_path):
    state = _setup_state(tmp_path)
    (tmp_path / "data" / STATE_FILE_NAME).write_text("{not json")
    os.chmod(tmp_path / "data" / STATE_FILE_NAME, 0o600)
    path = tmp_path / "totp.secret"
    term = _Term(["VALID"])
    with pytest.raises(CliError, match="step-up state"):
        _setup(path, term, tmp_path, state=state)
    assert not path.exists()
    assert "otpauth" not in term.out.getvalue()  # refused before any secret was shown


def test_c47_setup_code_cannot_be_replayed_to_approve(tmp_path):
    # End to end: the code typed at setup must not approve a request in the same step.
    gid = _other_gid()
    with (
        claudia_app(tmp_path, write_secret=False, totp_gids=(gid,)) as rig,
        TestClient(rig.app) as client,
    ):
        now = rig.clock.now().timestamp()
        term = _Term(["VALID"])
        state = FileStepUpState(Path(rig.core.settings.data_dir) / "claudia")
        assert (
            totp_setup(
                rig.secret_path,
                term.io(now),
                rotate=False,
                group=str(gid),
                state=state,
                admin_uid=os.geteuid(),
                groups=_Groups(),
            )
            == 0
        )
        secret = term._printed_secret()
        setup_code = totp_at(secret, now)
        _tapped(client, rig)
        assert _code(client, rig, setup_code, 1) == "refused"
        rig.clock.advance(timedelta(seconds=30))
        assert _code(client, rig, totp_at(secret, now + 30), 2) == "accepted"


class _RecordingState(FileStepUpState):
    """Records whether each load/save ran inside `exclusive()` (storage-totp-3)."""

    def __init__(self, directory: Path) -> None:
        super().__init__(directory)
        self.held = False
        self.calls: list[tuple[str, bool]] = []

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[None]:
        with super().exclusive():
            self.held = True
            try:
                yield
            finally:
                self.held = False

    def load(self) -> StepUpState:
        self.calls.append(("load", self.held))
        return super().load()

    def save(self, state: StepUpState) -> None:
        self.calls.append(("save", self.held))
        super().save(state)


def test_storage_totp_3_setup_burns_the_step_under_the_lock(tmp_path):
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    state = _RecordingState(data)
    assert _setup(tmp_path / "totp.secret", _Term(["VALID"]), tmp_path, state=state) == 0
    # Every state access (the early check and the burn) held the admin's lock.
    assert state.calls == [("load", True), ("load", True), ("save", True)]
