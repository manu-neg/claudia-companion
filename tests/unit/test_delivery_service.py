"""Unit tests for DeliveryService: routing to channels, retries, taps and their acks.

Runs the notifier-side service against a real in-memory admin core through
`InProcessDeliveryQueue`, so a question is followed from `ask` to the
edited message.
"""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest

from preview_dashboard.application.delivery import (
    ACK_NOT_RECORDED,
    DeliveryService,
    ack_text,
)
from preview_dashboard.application.questions import AskCommand
from preview_dashboard.domain.notifications import (
    DeliveryPayload,
    DeliveryState,
    backoff_delay,
)
from preview_dashboard.domain.questions import AnswerResult, QuestionState
from preview_dashboard.ports.notify import AnswerEvent, AnswerSource, NotificationChannel
from tests.builders import ulid
from tests.fakes import FakeAnswerSource, FakeNotificationChannel, InProcessDeliveryQueue
from tests.notify_support import NotifyHarness, build_harness

pytestmark = pytest.mark.unit

ASK = AskCommand(
    session_label="s1", prompt="Which DB?", options=[("a", "SQLite"), ("b", "Postgres")]
)


class Rig:
    """Admin harness + notifier-side service wired together in memory."""

    def __init__(self, *, fail_times: int = 0, refs: bool = True) -> None:
        self.h: NotifyHarness = build_harness(channels=("fake",))
        self.channel = FakeNotificationChannel("fake", fail_times=fail_times, refs=refs)
        self.source = FakeAnswerSource("telegram")
        self.queue = InProcessDeliveryQueue(
            outbox=self.h.outbox_service, questions=self.h.questions
        )
        self.service = DeliveryService(
            queue=self.queue,
            channels=[self.channel],
            answers=self.source,
            wait_seconds=60,
            poll_seconds=50,
        )

    def tap(self, question_id: str, key: str, handle: str = "cb-1") -> None:
        self.source.push(
            AnswerEvent(question_id=question_id, key=key, actor_ref="42", ack_handle=handle)
        )


def test_fakes_satisfy_notifier_ports_statically() -> None:
    channel: NotificationChannel = FakeNotificationChannel()
    source: AnswerSource = FakeAnswerSource()
    del channel, source


def test_question_round_trip() -> None:
    rig = Rig()
    q = rig.h.questions.ask(ASK)

    assert rig.service.run_once_deliveries() == 1
    (sent,) = rig.channel.sent
    assert sent.question_id == q.id
    assert [b.key for b in sent.content.buttons] == ["a", "b"]
    assert rig.queue.waits == [60]
    assert rig.h.outbox.message_ref_for(q.id, "fake") == "msg-1"

    rig.tap(q.id, "b")
    assert rig.service.run_once_answers() == 1
    assert rig.source.polls == [50]
    assert rig.source.acks == [("cb-1", "Recorded: b")]
    assert rig.queue.submitted == [(q.id, "b", "telegram", "42")]
    assert rig.h.repo.get(q.id).state is QuestionState.ANSWERED

    assert rig.service.run_once_deliveries() == 1
    ((ref, payload),) = rig.channel.resolved
    assert ref == "msg-1"
    assert payload.final_state is QuestionState.ANSWERED
    assert payload.content.buttons == ()
    assert payload.content.text.endswith("Answered: Postgres")
    assert {t.state for t in rig.h.outbox.tasks.values()} == {DeliveryState.DONE}


def test_late_taps_get_the_outcome() -> None:
    rig = Rig()
    q = rig.h.questions.ask(ASK)
    rig.tap(q.id, "a", "t1")
    rig.tap(q.id, "b", "t2")
    rig.tap(q.id, "zz", "t3")
    rig.tap(ulid(999), "a", "t4")
    assert rig.service.run_once_answers() == 1
    assert rig.source.acks == [
        ("t1", "Recorded: a"),
        ("t2", "Already answered"),
        ("t3", "Unknown"),
        ("t4", "Unknown"),
    ]


def test_channel_failure_backs_off_and_retries() -> None:
    rig = Rig(fail_times=1)
    rig.h.notify.notify("done", "ok")
    assert rig.service.run_once_deliveries() == 0
    (task,) = rig.h.outbox.tasks.values()
    assert (task.attempts, task.state) == (1, DeliveryState.PENDING)
    assert rig.service.run_once_deliveries() == 0  # not due yet
    rig.h.clock.advance(backoff_delay(1))
    assert rig.service.run_once_deliveries() == 1
    assert len(rig.channel.sent) == 1


def test_unknown_channel_is_reported_failed() -> None:
    rig = Rig()
    other = build_harness(channels=("elsewhere",))
    queue = InProcessDeliveryQueue(outbox=other.outbox_service, questions=other.questions)
    service = DeliveryService(queue=queue, channels=[rig.channel])
    other.notify.notify("done", "ok")
    assert service.run_once_deliveries() == 0
    (task,) = other.outbox.tasks.values()
    assert task.attempts == 1
    assert rig.channel.sent == []


class _BadRefChannel(FakeNotificationChannel):
    def send(self, payload: DeliveryPayload) -> str | None:
        super().send(payload)
        return "not a valid ref"


def test_invalid_message_ref_is_dropped_not_resent() -> None:
    rig = Rig()
    channel = _BadRefChannel("fake")
    service = DeliveryService(queue=rig.queue, channels=[channel])
    q = rig.h.questions.ask(ASK)
    assert service.run_once_deliveries() == 1
    assert rig.h.outbox.message_ref_for(q.id, "fake") is None
    rig.h.questions.cancel(q.id)
    assert service.run_once_deliveries() == 0  # RESOLVE dropped: nothing to edit
    assert channel.resolved == []
    assert len(channel.sent) == 1


def test_channel_without_refs_drops_later_resolves() -> None:
    rig = Rig(refs=False)
    q = rig.h.questions.ask(ASK)
    rig.service.run_once_deliveries()
    rig.h.questions.answer(q.id, "a", "telegram")
    assert rig.service.run_once_deliveries() == 0
    assert rig.channel.resolved == []


def test_queue_errors_propagate_for_the_loop_to_back_off() -> None:
    rig = Rig()
    rig.queue.down = True
    with pytest.raises(ConnectionError):
        rig.service.run_once_deliveries()


def test_unreachable_admin_acks_not_recorded() -> None:
    rig = Rig()
    q = rig.h.questions.ask(ASK)
    rig.queue.down = True
    rig.tap(q.id, "a")
    assert rig.service.run_once_answers() == 0
    assert rig.source.acks == [("cb-1", ACK_NOT_RECORDED)]
    assert rig.h.repo.get(q.id).state is QuestionState.OPEN


def test_ack_failure_does_not_lose_the_answer() -> None:
    rig = Rig()
    q = rig.h.questions.ask(ASK)

    def broken_ack(handle: str, text: str) -> None:
        raise TimeoutError("ack")

    rig.source.ack = broken_ack  # type: ignore[method-assign]
    rig.tap(q.id, "a")
    assert rig.service.run_once_answers() == 1
    assert rig.h.repo.get(q.id).answer_key == "a"


def test_no_answer_source() -> None:
    rig = Rig()
    service = DeliveryService(queue=rig.queue, channels=[rig.channel])
    assert service.run_once_answers() == 0


@pytest.mark.parametrize(
    ("result", "text"),
    [
        (AnswerResult.RECORDED, "Recorded: b"),
        (AnswerResult.ALREADY_ANSWERED, "Already answered"),
        (AnswerResult.EXPIRED, "Expired"),
        (AnswerResult.CANCELLED, "Withdrawn"),
        (AnswerResult.UNKNOWN, "Unknown"),
    ],
)
def test_ack_texts(result: AnswerResult, text: str) -> None:
    assert ack_text(result, "b") == text


def test_constructor_checks() -> None:
    rig = Rig()
    with pytest.raises(ValueError, match="unique"):
        DeliveryService(queue=rig.queue, channels=[rig.channel, FakeNotificationChannel("fake")])
    with pytest.raises(ValueError, match="waits"):
        DeliveryService(queue=rig.queue, channels=[], wait_seconds=0)


def test_expired_question_edits_the_message() -> None:
    rig = Rig()
    rig.h.questions.ask(ASK)
    rig.service.run_once_deliveries()
    rig.h.clock.advance(timedelta(hours=24))
    assert rig.h.questions.expire_due() == 1
    rig.service.run_once_deliveries()
    ((_, payload),) = rig.channel.resolved
    assert payload.final_state is QuestionState.EXPIRED


def test_failure_logs_only_the_exception_type(caplog: pytest.LogCaptureFixture) -> None:
    secret_url = "https://api.telegram.org/bot123456:SECRET-TOKEN/sendMessage"  # noqa: S105

    class Leaky(FakeNotificationChannel):
        def send(self, payload: DeliveryPayload) -> str | None:
            raise ConnectionError(f"failed to POST {secret_url}")

    rig = Rig()
    service = DeliveryService(queue=rig.queue, channels=[Leaky("fake")])
    rig.h.notify.notify("done", "private title")
    with caplog.at_level(logging.DEBUG):
        service.run_once_deliveries()
    assert "ConnectionError" in caplog.text
    assert "SECRET-TOKEN" not in caplog.text
    assert "private title" not in caplog.text
