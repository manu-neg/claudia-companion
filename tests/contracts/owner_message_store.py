"""Contract test suite for the OwnerMessageStore port (ADR 0031, C44), plus its builders.

Subclass `OwnerMessageStoreContract` and override the `ms` fixture
(returning `MessageStore(store, corrupt)` over an empty backend); it runs
against the in-memory fake and the SQLite adapter, so they cannot drift.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from preview_dashboard.domain.errors import (
    AlreadyExistsError,
    InvalidStateError,
    NotFoundError,
    ValidationError,
)
from preview_dashboard.domain.owner_messages import InboxState, OwnerMessage, OwnerMessageId
from preview_dashboard.ports.owner_messages import OwnerMessageStore
from tests.builders import T0, ulid

# Hostile-but-valid text: must round-trip verbatim (C24, C48 needs invisible chars).
HOSTILE_TEXTS = (
    "Robert'); DROP TABLE owner_messages;--",
    "x' OR '1'='1",
    "zero\u200bwidth \u202eoverride\u202c and tabs\tand\nlines",
    "\ufb01 \uff26\uff35\uff2c\uff2c \uff57\uff49\uff44\uff54\uff48 \u2014 "
    "\U0001f642\U0001f44d\U0001f3fd",  # ligature, full-width, emoji + skin tone
    "  leading and trailing spaces  ",
)


def mid(n: int) -> OwnerMessageId:
    """Deterministic owner message id (kept apart from item ids used in tests)."""
    return OwnerMessageId(ulid(60_000 + n))


def make_message(n: int = 1, **overrides: Any) -> OwnerMessage:
    """A RECEIVED message `mid(n)` for update `n`, Telegram message `100 + n`, at T0 + n s."""
    fields: dict[str, Any] = {
        "id": mid(n),
        "update_id": n,
        "telegram_message_id": 100 + n,
        "text": f"Hello Claudia, message {n}",
        "received_at": T0 + timedelta(seconds=n),
    }
    fields.update(overrides)
    return OwnerMessage.new(**fields)


@dataclass(frozen=True)
class MessageStore:
    """An owner-message store over an empty backend plus its tamper hook."""

    store: OwnerMessageStore
    corrupt: Callable[[OwnerMessageId], None]


class OwnerMessageStoreContract:
    """Behaviour every OwnerMessageStore must have."""

    @pytest.fixture
    def ms(self) -> MessageStore:
        raise NotImplementedError("override the `ms` fixture in the concrete test class")

    def test_round_trip_with_every_field(self, ms: MessageStore) -> None:
        message = make_message(
            1,
            is_forwarded=True,
            reply_to_message_id=7,
            quote_text="quoted bit",
            received_at=T0.replace(microsecond=123456),
        )
        assert ms.store.add(message) == message
        assert ms.store.get(message.id) == message

    @pytest.mark.parametrize("text", HOSTILE_TEXTS)
    def test_untrusted_text_round_trips_verbatim(self, ms: MessageStore, text: str) -> None:
        message = make_message(1, text=text, quote_text=text)
        ms.store.add(message)
        ms.store.add(make_message(2))
        got = ms.store.get(message.id)
        assert (got.text, got.quote_text) == (text, text)
        assert ms.store.get(mid(2)).text == "Hello Claudia, message 2"

    def test_non_utc_input_round_trips_as_same_instant(self, ms: MessageStore) -> None:
        tz = timezone(timedelta(hours=-3))
        message = make_message(1, received_at=T0.astimezone(tz))
        ms.store.add(message)
        assert ms.store.get(message.id).received_at == T0

    def test_get_missing(self, ms: MessageStore) -> None:
        with pytest.raises(NotFoundError):
            ms.store.get(mid(9))

    def test_redelivered_update_is_stored_once(self, ms: MessageStore) -> None:
        first = make_message(1)
        assert ms.store.add(first) == first
        again = make_message(2, update_id=1, telegram_message_id=101, text="other")
        assert ms.store.add(again) == first  # the stored one, nothing new
        with pytest.raises(NotFoundError):
            ms.store.get(again.id)
        assert ms.store.list_unhandled(10) == [first]

    def test_same_update_other_message_id_is_a_new_row(self, ms: MessageStore) -> None:
        ms.store.add(make_message(1))
        other = make_message(2, update_id=1)
        assert ms.store.add(other) == other

    def test_duplicate_id_for_another_update_is_refused(self, ms: MessageStore) -> None:
        first = make_message(1)
        ms.store.add(first)
        with pytest.raises(AlreadyExistsError):
            ms.store.add(make_message(1, update_id=50, telegram_message_id=500))
        assert ms.store.get(first.id) == first

    def test_only_received_messages_are_added(self, ms: MessageStore) -> None:
        handled = make_message(1).handled(T0 + timedelta(minutes=1))
        with pytest.raises(ValidationError):
            ms.store.add(handled)
        with pytest.raises(NotFoundError):
            ms.store.get(handled.id)

    def test_list_unhandled_order_and_limit(self, ms: MessageStore) -> None:
        for n in (3, 1, 2):
            ms.store.add(make_message(n))
        tie = make_message(4, received_at=T0 + timedelta(seconds=1))
        ms.store.add(tie)
        assert [m.id for m in ms.store.list_unhandled(10)] == [mid(1), tie.id, mid(2), mid(3)]
        assert [m.id for m in ms.store.list_unhandled(2)] == [mid(1), tie.id]

    @pytest.mark.parametrize("limit", [0, 101, -1, True])
    def test_list_unhandled_limit_out_of_range(self, ms: MessageStore, limit: int) -> None:
        with pytest.raises(ValidationError):
            ms.store.list_unhandled(limit)

    def test_mark_handled_once(self, ms: MessageStore) -> None:
        ms.store.add(make_message(1))
        ms.store.add(make_message(2))
        at = T0 + timedelta(minutes=1)
        handled = ms.store.mark_handled(mid(1), at)
        assert (handled.state, handled.handled_at) == (InboxState.HANDLED, at)
        assert ms.store.get(mid(1)) == handled
        assert [m.id for m in ms.store.list_unhandled(10)] == [mid(2)]
        with pytest.raises(InvalidStateError):
            ms.store.mark_handled(mid(1), at + timedelta(seconds=1))
        assert ms.store.get(mid(1)) == handled

    def test_mark_handled_errors(self, ms: MessageStore) -> None:
        ms.store.add(make_message(1))
        with pytest.raises(NotFoundError):
            ms.store.mark_handled(mid(9), T0 + timedelta(minutes=1))
        with pytest.raises(ValidationError):
            ms.store.mark_handled(mid(1), datetime(2026, 1, 1, 13))  # naive
        with pytest.raises(ValidationError):
            ms.store.mark_handled(mid(1), T0 - timedelta(days=1))  # before received
        assert ms.store.get(mid(1)).state is InboxState.RECEIVED

    def test_delete_received_before_is_strict_and_covers_every_state(
        self, ms: MessageStore
    ) -> None:
        ms.store.add(make_message(1))
        ms.store.add(make_message(2))
        ms.store.add(make_message(3))
        ms.store.mark_handled(mid(1), T0 + timedelta(minutes=1))
        assert ms.store.delete_received_before(T0 + timedelta(seconds=1)) == 0
        assert ms.store.delete_received_before(T0 + timedelta(seconds=3)) == 2
        for n in (1, 2):
            with pytest.raises(NotFoundError):
                ms.store.get(mid(n))
        assert ms.store.get(mid(3)).id == mid(3)

    def test_deleted_update_can_arrive_again(self, ms: MessageStore) -> None:
        ms.store.add(make_message(1))
        ms.store.delete_received_before(T0 + timedelta(days=1))
        again = make_message(2, update_id=1, telegram_message_id=101)
        assert ms.store.add(again) == again

    def test_naive_times_are_rejected(self, ms: MessageStore) -> None:
        with pytest.raises(ValidationError):
            ms.store.delete_received_before(datetime(2026, 1, 1, 12))

    def test_tampered_row_fails_closed_and_is_skipped(self, ms: MessageStore) -> None:
        ms.store.add(make_message(1))
        ms.store.add(make_message(2))
        ms.corrupt(mid(1))
        with pytest.raises(ValidationError):
            ms.store.get(mid(1))
        assert [m.id for m in ms.store.list_unhandled(10)] == [mid(2)]
        with pytest.raises(ValidationError):
            ms.store.mark_handled(mid(1), T0 + timedelta(minutes=1))
