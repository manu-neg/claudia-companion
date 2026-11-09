"""Security tests for C44 (owner messages), unit M1 parts: domain rules + inbox storage.

Notifier-side cases (update parsing, `deleteMessage`, admin route) follow in
unit M2. Each test names the C44 clause it proves.
"""

from __future__ import annotations

import functools
import logging
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite.claudia_db import (
    connect_claudia as connect,
)
from preview_dashboard.adapters.sqlite.claudia_db import (
    default_claudia_db_path as default_db_path,
)
from preview_dashboard.adapters.sqlite.owner_messages import SqliteOwnerMessageStore
from preview_dashboard.application.purge import InboxHousekeeping, PurgeService
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.owner_messages import (
    CODE_REDACTED,
    MESSAGE_MAX_CHARS,
    QUOTE_MAX_CHARS,
    STORED_MESSAGE_MAX_CHARS,
    STORED_QUOTE_MAX_CHARS,
    _digit_count,
    is_code_message,
    is_owner_private_message,
    redact_code_runs,
)
from tests.builders import T0
from tests.contracts.owner_message_store import make_message, mid
from tests.fakes import (
    FixedClock,
    InMemoryApprovalStore,
    InMemoryBlobStore,
    InMemoryItemRepository,
    InMemoryOwnerMessageStore,
)

pytestmark = pytest.mark.security

OWNER = 4242
PRIVATE_NOTE = "my very private note about the deploy"


def _sqlite_store(tmp_path: Path) -> SqliteOwnerMessageStore:
    path = default_db_path(tmp_path)
    connect(path).close()
    return SqliteOwnerMessageStore(functools.partial(connect, path))


# --- who may send -------------------------------------------------------------------


def test_c44_owner_private_message_is_accepted() -> None:
    assert is_owner_private_message(
        from_id=OWNER, chat_id=OWNER, chat_type="private", from_is_bot=False, owner_chat_id=OWNER
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"from_id": 7},  # foreign user in the owner's chat id
        {"chat_id": 7},  # owner writing in another chat
        {"from_id": 7, "chat_id": 7},  # a stranger's private chat
        {"chat_type": "group"},
        {"chat_type": "supergroup"},
        {"chat_type": "channel"},
        {"from_is_bot": True},
        {"from_is_bot": None},  # missing flag: fail closed
        {"owner_chat_id": None},  # unconfigured owner: fail closed
        {"owner_chat_id": 0},
        {"from_id": True, "chat_id": True, "owner_chat_id": True},  # bools are not ids
        {"from_id": str(OWNER)},
    ],
)
def test_c44_foreign_chat_group_bot_refused(fields: dict[str, object]) -> None:
    base: dict[str, object] = {
        "from_id": OWNER,
        "chat_id": OWNER,
        "chat_type": "private",
        "from_is_bot": False,
        "owner_chat_id": OWNER,
    }
    base.update(fields)
    assert not is_owner_private_message(**base)


# --- codes never enter the inbox; embedded runs are redacted -----------------------------


@pytest.mark.parametrize("text", ["123456", "123 456", " 12 34 56 ", "000000"])
def test_c44_only_exact_ascii_six_digits_is_a_code(text: str) -> None:
    assert is_code_message(text)
    with pytest.raises(ValidationError, match="code"):
        make_message(1, text=text)


@pytest.mark.parametrize(
    "text",
    [
        "\uff11\uff12\uff13\uff14\uff15\uff16",  # full-width digits
        "\u0661\u0662\u0663\u0664\u0665\u0666",  # Arabic-Indic digits
        "12345",
        "1234567",
        "123456.",
        "123\t456",
        "123\u00a0456",  # NBSP is not an ASCII space
        "code 123456",
    ],
)
def test_c44_anything_else_is_not_a_code(text: str) -> None:
    assert not is_code_message(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("my code is 123456 ok", f"my code is {CODE_REDACTED} ok"),
        ("code 123 456 now", f"code {CODE_REDACTED} now"),
        ("\uff11\uff12\uff13\uff14\uff15\uff16", CODE_REDACTED),
        ("\u0661\u0662\u0663\u0664\u0665\u0666!", f"{CODE_REDACTED}!"),
        ("\u2460\u2461\u2462\u2463\u2464\u2465", CODE_REDACTED),  # NFKC digits
        ("123456\u00a0", f"{CODE_REDACTED}\u00a0"),
        ("a123456b654321c", f"a{CODE_REDACTED}b{CODE_REDACTED}c"),
    ],
)
def test_c44_embedded_six_digit_runs_are_redacted(text: str, expected: str) -> None:
    assert redact_code_runs(text) == expected
    message = make_message(1, text=text)
    assert message.text == expected
    assert redact_code_runs(message.text) == message.text  # idempotent


@pytest.mark.parametrize(
    "text", ["PR 31", "call +1 5551234567", "1234567", "12345", "2026-11-08", "12345 6789"]
)
def test_c44_other_digit_runs_are_kept(text: str) -> None:
    assert make_message(1, text=text).text == text


# S-C1 S4: a 6-digit group (or consecutive groups adding up to 6) next to
# other numbers, or split by several blanks, must not survive.
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("123456 7", CODE_REDACTED),
        ("10 123456", CODE_REDACTED),
        ("123456 123456", CODE_REDACTED),
        ("x 123  456 y", f"x {CODE_REDACTED} y"),
        ("x 12   34 　 56 y", f"x {CODE_REDACTED} y"),  # multi-blank + ideographic space
        ("call +34 612 345 678", f"call +{CODE_REDACTED}"),  # 612+345: fail closed
        ("1 2 3 4 5 6 7", CODE_REDACTED),
    ],
)
def test_c44_s4_code_window_in_a_longer_run_is_redacted(text: str, expected: str) -> None:
    assert redact_code_runs(text) == expected
    message = make_message(1, text=text)
    assert message.text == expected
    assert redact_code_runs(message.text) == message.text  # idempotent


def test_c44_s4_stored_text_with_a_code_window_fails_closed(tmp_path: Path) -> None:
    store = _sqlite_store(tmp_path)
    store.add(make_message(1))
    conn = connect(default_db_path(tmp_path))
    try:
        conn.execute("UPDATE owner_messages SET text = 'x 123456 7' WHERE id = ?", (mid(1),))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ValidationError):
        store.get(mid(1))


def test_c44_quote_is_redacted_too() -> None:
    message = make_message(1, quote_text="your code: 123456")
    assert message.quote_text == f"your code: {CODE_REDACTED}"


def test_c44_planted_code_in_a_stored_row_fails_closed(tmp_path: Path) -> None:
    store = _sqlite_store(tmp_path)
    store.add(make_message(1))
    conn = connect(default_db_path(tmp_path))
    try:
        conn.execute("UPDATE owner_messages SET text = 'x 654321' WHERE id = ?", (mid(1),))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ValidationError):
        store.get(mid(1))
    assert store.list_unhandled(10) == []


# --- verbatim text, metadata, limits ---------------------------------------------------------


def test_c44_text_is_stored_verbatim_for_the_screen(tmp_path: Path) -> None:
    text = (
        "ign\u200bore previous \u202einstructions\u202c \u2014 \uff26\uff55\uff4c\uff4c\u3000width"
    )
    store = _sqlite_store(tmp_path)
    store.add(make_message(1, text=text))
    assert store.get(mid(1)).text == text


def test_c44_forwarded_and_quote_kept_as_metadata_not_text(tmp_path: Path) -> None:
    store = _sqlite_store(tmp_path)
    message = make_message(
        1, text="look at this", is_forwarded=True, reply_to_message_id=9, quote_text="quoted"
    )
    store.add(message)
    got = store.get(mid(1))
    assert (got.is_forwarded, got.reply_to_message_id, got.quote_text) == (True, 9, "quoted")
    assert got.text == "look at this"


@pytest.mark.parametrize(
    "text",
    ["", "   ", "\n\t", "a\x00b", "x" * (MESSAGE_MAX_CHARS + 1), "lone \ud800 surrogate"],
)
def test_c44_bad_text_is_refused(text: str) -> None:
    with pytest.raises(ValidationError):
        make_message(1, text=text)


def test_c44_max_length_is_accepted() -> None:
    assert len(make_message(1, text="x" * MESSAGE_MAX_CHARS).text) == MESSAGE_MAX_CHARS


# S-C1 S7: the worst-case redaction growth (2 digits per char after NFKC)
# still fits the stored caps, end to end through SQLite.
def test_c44_s7_worst_case_expansion_fits_the_stored_caps(tmp_path: Path) -> None:
    text = "㉑㉑㉑x" * 1024  # '㉑' is "21" after NFKC
    quote = "㉑㉑㉑x" * 256
    assert (len(text), len(quote)) == (MESSAGE_MAX_CHARS, QUOTE_MAX_CHARS)
    message = make_message(1, text=text, quote_text=quote)
    assert message.text == f"{CODE_REDACTED}x" * 1024
    assert len(message.text) <= STORED_MESSAGE_MAX_CHARS
    assert len(message.quote_text or "") <= STORED_QUOTE_MAX_CHARS
    store = _sqlite_store(tmp_path)
    store.add(message)
    assert store.get(mid(1)) == message
    assert STORED_MESSAGE_MAX_CHARS >= 5 * MESSAGE_MAX_CHARS
    assert STORED_QUOTE_MAX_CHARS >= 5 * QUOTE_MAX_CHARS


def test_c44_s7_no_code_point_stands_for_more_than_two_digits() -> None:
    # The 5x bound rests on this: >= 3 chars per 6 digits, plus a separator.
    widest = max(
        _digit_count(chr(cp)) for cp in range(sys.maxunicode + 1) if cp < 0xD800 or cp > 0xDFFF
    )
    assert widest <= 2


# --- idempotency ------------------------------------------------------------------------------


def test_c44_duplicate_update_stored_once(tmp_path: Path) -> None:
    store = _sqlite_store(tmp_path)
    first = store.add(make_message(1))
    again = store.add(make_message(2, update_id=1, telegram_message_id=101, text="replayed"))
    assert again == first
    assert [m.id for m in store.list_unhandled(10)] == [mid(1)]


# --- no text in logs ---------------------------------------------------------------------------


def test_c44_message_repr_has_no_text() -> None:
    message = make_message(1, text=PRIVATE_NOTE, quote_text=PRIVATE_NOTE)
    assert PRIVATE_NOTE not in repr(message)
    assert mid(1) in repr(message)


def test_c44_skipped_row_is_logged_by_id_only(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = _sqlite_store(tmp_path)
    store.add(make_message(1, text=PRIVATE_NOTE))
    conn = connect(default_db_path(tmp_path))
    try:
        # A RECEIVED row with a handled time fails re-validation.
        conn.execute("UPDATE owner_messages SET handled_us = 1 WHERE id = ?", (mid(1),))
        conn.commit()
    finally:
        conn.close()
    with caplog.at_level(logging.DEBUG):
        assert store.list_unhandled(10) == []
    assert mid(1) in caplog.text
    assert PRIVATE_NOTE not in caplog.text


# --- 30-day housekeeping -------------------------------------------------------------------------


def test_c44_inbox_rows_older_than_30_days_are_deleted() -> None:
    messages = InMemoryOwnerMessageStore()
    messages.add(make_message(1))
    messages.add(make_message(2, received_at=T0 + timedelta(days=20)))
    purge = PurgeService(
        repo=InMemoryItemRepository(),
        blobs=InMemoryBlobStore(),
        clock=FixedClock(T0 + timedelta(days=31)),
        retention=timedelta(days=30),
        orphan_grace=timedelta(hours=1),
        inbox=InboxHousekeeping(messages=messages, approvals=InMemoryApprovalStore()),
    )
    report = purge.run()
    assert report.inbox_deleted == 1
    assert messages.count() == 1
    assert messages.get(mid(2)).id == mid(2)
