"""Unit tests for bot pairing (`notify pair`): only `/start <code>` from a private chat matches."""

from __future__ import annotations

from typing import Any

import pytest

from preview_dashboard.adapters.telegram.pairing import (
    CODE_ALPHABET,
    CODE_LENGTH,
    PairingTimeoutError,
    match_start,
    new_pairing_code,
    wait_for_pairing,
)
from tests.telegram_support import OWNER, STRANGER, FakeBotApi, ok

pytestmark = pytest.mark.unit

CODE = "ABCD2345"


def start(
    update_id: int, text: str, *, sender: int = OWNER, chat: int = OWNER, kind: str = "private"
) -> dict[str, Any]:
    return {
        "update_id": update_id,
        "message": {
            "message_id": 1,
            "from": {"id": sender},
            "chat": {"id": chat, "type": kind},
            "text": text,
        },
    }


def test_codes_are_random_and_well_formed() -> None:
    codes = {new_pairing_code() for _ in range(50)}
    assert len(codes) == 50
    assert all(len(c) == CODE_LENGTH and set(c) <= set(CODE_ALPHABET) for c in codes)


def test_match_start_accepts_only_the_exact_code_in_a_private_chat() -> None:
    assert match_start(start(1, f"/start {CODE}"), CODE) == OWNER
    assert match_start(start(1, f"/start {CODE}\n"), CODE) == OWNER
    for update in (
        start(1, "/start WRONG123"),
        start(1, f"/start {CODE.lower()}"),
        start(1, f"/start {CODE} extra"),
        start(1, f"/start {CODE}", sender=STRANGER),
        start(1, f"/start {CODE}", chat=-100, sender=-100, kind="group"),
        start(1, f"/start {CODE}", kind="group"),
        {"update_id": 1},
        "junk",
    ):
        assert match_start(update, CODE) is None


def test_wait_for_pairing_returns_the_chat_and_confirms_the_offset() -> None:
    api = FakeBotApi()
    api.script("getUpdates", ok([start(5, "hello")]), ok([start(6, f"/start {CODE}")]))
    assert wait_for_pairing(api.client(), CODE, timeout=100) == OWNER
    bodies = [c.body for c in api.calls]
    assert bodies[0]["allowed_updates"] == ["message"]
    assert bodies[1]["offset"] == 6
    assert bodies[2] == {"offset": 7, "timeout": 0}


def test_wait_for_pairing_times_out() -> None:
    now = [0.0]

    def clock() -> float:
        now[0] += 30.0
        return now[0]

    api = FakeBotApi()
    with pytest.raises(PairingTimeoutError):
        wait_for_pairing(api.client(), CODE, timeout=60, monotonic=clock)
