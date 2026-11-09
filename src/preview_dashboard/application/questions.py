"""QuestionService: ask the owner a choice question, record the first answer, expire, cancel.

A question and its alert are committed together (transactional outbox);
every resolution is a compare-and-swap that also enqueues the RESOLVE
deliveries and wakes long-poll waiters. Only `answer` records an answer
and interfaces expose it to the notifier token alone (ADR 0021, C34).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from preview_dashboard.application.notify import (
    acquire_alert,
    content_texts,
    new_ulid,
    scan_texts,
    send_tasks,
    validate_channels,
)
from preview_dashboard.application.ratelimit import RateLimiter
from preview_dashboard.domain.errors import ConflictError, NotFoundError, ValidationError
from preview_dashboard.domain.models import ensure_utc, parse_item_id
from preview_dashboard.domain.notifications import (
    DashboardLinks,
    DeliveryTask,
    Notification,
    NotificationId,
    TaskId,
)
from preview_dashboard.domain.questions import (
    DEFAULT_QUESTION_TTL,
    MAX_OPTIONS,
    MAX_QUESTION_TTL,
    MIN_QUESTION_TTL,
    AnswerResult,
    Question,
    QuestionId,
    QuestionOption,
    QuestionState,
    parse_question_id,
    validate_plugin_name,
)
from preview_dashboard.events import (
    QUESTION_EVENT,
    EventRegistry,
    RenderContext,
    default_event_registry,
)
from preview_dashboard.ports.clock import Clock
from preview_dashboard.ports.ids import IdGenerator
from preview_dashboard.ports.notify import NotificationOutbox, OutboxEvents
from preview_dashboard.ports.questions import QuestionEvents, QuestionRepository
from preview_dashboard.ports.scanner import ContentScanner

_RESULT_FOR_STATE = {
    QuestionState.ANSWERED: AnswerResult.ALREADY_ANSWERED,
    QuestionState.EXPIRED: AnswerResult.EXPIRED,
    QuestionState.CANCELLED: AnswerResult.CANCELLED,
}


@dataclass(frozen=True, slots=True, kw_only=True)
class AskCommand:
    """Input of `QuestionService.ask` (raw, untrusted values).

    Attributes:
        prompt: the question (<= 200 chars after sanitizing).
        options: 2..8 `(key, label)` pairs, keys `[a-z0-9_-]{1,16}`.
        default_key: what the asker will assume if the question expires.
        item_id: dashboard item the question is about (becomes the link).
        session_label: which Claude session asks, 1..40 chars; required, shown
            in every alert. Reported by the caller, so unverified (C35).
        expires_in: lifetime, 60 s..7 d; None = the service default (24 h).
    """

    prompt: str
    options: Sequence[tuple[str, str]]
    session_label: str
    default_key: str | None = None
    item_id: str | None = None
    expires_in: timedelta | None = None


def _check_ttl(ttl: timedelta) -> timedelta:
    if not isinstance(ttl, timedelta) or not MIN_QUESTION_TTL <= ttl <= MAX_QUESTION_TTL:
        raise ValidationError("expiry must be between 60 seconds and 7 days")
    return ttl


class QuestionService:
    """Ask / get / answer / cancel / expire choice questions.

    Args:
        channels: enabled channel names; empty = notifications disabled
            (questions are still stored, no SEND tasks are created).
        ttl: default lifetime (60 s..7 d).
        rate_limiter: the alert budget shared with `NotifyService` (C37).
        links: builds the dashboard link of each alert (C35).
        outbox_events: woken whenever deliveries are enqueued (optional).

    Raises:
        ValueError: `ttl` out of range, duplicate channels.
        ValidationError: malformed channel name; no `question` event type.
    """

    def __init__(
        self,
        *,
        repo: QuestionRepository,
        outbox: NotificationOutbox,
        events: QuestionEvents,
        clock: Clock,
        ids: IdGenerator,
        scanner: ContentScanner,
        rate_limiter: RateLimiter,
        channels: Sequence[str],
        ttl: timedelta = DEFAULT_QUESTION_TTL,
        registry: EventRegistry | None = None,
        links: DashboardLinks | None = None,
        outbox_events: OutboxEvents | None = None,
    ) -> None:
        try:
            self._ttl = _check_ttl(ttl)
        except ValidationError as exc:
            raise ValueError(str(exc)) from None
        self._repo = repo
        self._outbox = outbox
        self._events = events
        self._clock = clock
        self._ids = ids
        self._scanner = scanner
        self._limiter = rate_limiter
        self._channels = validate_channels(channels)
        self._question_type = (registry or default_event_registry()).get(QUESTION_EVENT)
        self._links = links or DashboardLinks()
        self._outbox_events = outbox_events

    # --- use cases -----------------------------------------------------------

    def ask(self, cmd: AskCommand) -> Question:
        """Store a new OPEN question plus its alert (one SEND per enabled channel), atomically.

        Every attempt counts against the rate limit, including refused ones.

        Raises:
            RateLimitedError: alert budget used up.
            ValidationError: any invalid field (see `Question`), a missing
                session label, a link in any text (C35), bad expiry.
            SecretDetectedError: prompt, a key/label, the session label (raw
                or sanitized) or the rendered alert matches a secret rule.
        """
        acquire_alert(self._limiter)
        if not isinstance(cmd.session_label, str):
            raise ValidationError("session label is required")
        options = _build_options(cmd.options)
        ttl = self._ttl if cmd.expires_in is None else _check_ttl(cmd.expires_in)
        now = self._clock.now()
        question = Question.new(
            id=QuestionId(new_ulid(self._ids)),
            prompt=cmd.prompt,
            options=options,
            now=now,
            expires_at=now + ttl,
            default_key=cmd.default_key,
            item_id=None if cmd.item_id is None else parse_item_id(cmd.item_id),
            session_label=cmd.session_label,
        )
        content = self._question_type.render(self._context(question))
        # Everything that leaves the host is scanned: raw, sanitized and as
        # rendered (C35).
        raw_options = [text for key, label in cmd.options for text in (key, label)]
        scan_texts(
            self._scanner,
            (
                cmd.prompt,
                question.prompt,
                *raw_options,
                *(o.label for o in question.options),
                cmd.session_label,
                question.session_label,
                *content_texts(content),
            ),
        )
        notification = Notification(
            id=NotificationId(new_ulid(self._ids)),
            event_type=QUESTION_EVENT,
            title=question.prompt,
            created_at=now,
            item_id=question.item_id,
            question_id=question.id,
        )
        tasks = send_tasks(
            self._ids,
            notification_id=notification.id,
            channels=self._channels,
            content=content,
            now=now,
        )
        self._repo.add_with_notification(question, notification, tasks)
        self._wake_notifier(tasks)
        return question

    def get(self, question_id: str) -> Question:
        """Return a question; an OPEN one past its deadline is expired first (lazily).

        Raises:
            ValidationError: malformed id.
            NotFoundError: no such question.
            ConflictError: it changed concurrently twice in a row.
        """
        qid = parse_question_id(question_id)
        return self._retry_once(lambda: self._expire_if_due(self._repo.get(qid)))

    def answer(self, question_id: str, key: str, source: str) -> AnswerResult:
        """Record the owner's choice; the first answer wins.

        Untrusted `question_id`/`key` (channel callback data) never raise:
        anything the question did not offer is UNKNOWN. An OPEN question
        past its deadline is expired instead (EXPIRED), never answered.

        Raises:
            ValidationError: malformed `source` (a configuration error).
            ConflictError: the question changed concurrently twice in a row.
        """
        validate_plugin_name(source, "answer source")
        try:
            qid = parse_question_id(question_id)
        except ValidationError:
            return AnswerResult.UNKNOWN
        return self._retry_once(lambda: self._answer_once(qid, key, source))

    def cancel(self, question_id: str) -> Question:
        """Withdraw an OPEN question; a resolved one is returned unchanged (idempotent).

        An OPEN question already past its deadline is expired instead.

        Raises:
            ValidationError: malformed id.
            NotFoundError: no such question.
            ConflictError: it changed concurrently twice in a row.
        """
        qid = parse_question_id(question_id)
        return self._retry_once(lambda: self._cancel_once(self._repo.get(qid)))

    def expire_due(self, now: datetime | None = None) -> int:
        """Expire every OPEN question whose deadline has passed; return how many.

        A question changed concurrently (answered, cancelled) is skipped.

        Raises:
            ValidationError: `now` is naive.
        """
        at = self._clock.now() if now is None else ensure_utc(now, "now")
        expired = 0
        for question in self._repo.list_expirable(at):
            if question.state is not QuestionState.OPEN:
                continue
            try:
                self._commit(question, question.expired(question.next_change_at(at)))
            except (ConflictError, NotFoundError):
                continue  # someone else resolved or purged it meanwhile
            expired += 1
        return expired

    # --- steps (each runs once per attempt; ConflictError -> one retry) -------

    def _answer_once(self, qid: QuestionId, key: str, source: str) -> AnswerResult:
        try:
            question = self._repo.get(qid)
        except NotFoundError:
            return AnswerResult.UNKNOWN
        if question.option(key) is None:
            return AnswerResult.UNKNOWN
        if question.state is not QuestionState.OPEN:
            return _RESULT_FOR_STATE[question.state]
        at = question.next_change_at(self._clock.now())
        if question.is_expired(at):
            self._commit(question, question.expired(at))
            return AnswerResult.EXPIRED
        self._commit(question, question.answered(key, source, at))
        return AnswerResult.RECORDED

    def _cancel_once(self, question: Question) -> Question:
        if question.state is not QuestionState.OPEN:
            return question
        at = question.next_change_at(self._clock.now())
        changed = question.expired(at) if question.is_expired(at) else question.cancelled(at)
        self._commit(question, changed)
        return changed

    def _expire_if_due(self, question: Question) -> Question:
        now = self._clock.now()
        if question.state is not QuestionState.OPEN or not question.is_expired(now):
            return question
        changed = question.expired(question.next_change_at(now))
        self._commit(question, changed)
        return changed

    # --- internals -----------------------------------------------------------

    @staticmethod
    def _retry_once[T](step: Callable[[], T]) -> T:
        try:
            return step()
        except ConflictError:
            # Re-read: the other writer usually resolved it (first wins),
            # and the step then just reports that. A second conflict -> 409.
            return step()

    def _commit(self, old: Question, new: Question) -> None:
        """CAS-save a resolution with its RESOLVE tasks, then wake waiters (after commit)."""
        tasks = self._resolve_tasks(new)
        self._repo.save(new, expected_updated_at=old.updated_at, tasks=tasks)
        self._events.notify(new.id)
        self._wake_notifier(tasks)

    def _resolve_tasks(self, question: Question) -> tuple[DeliveryTask, ...]:
        """RESOLVE deliveries turning the alert into the outcome (buttons removed)."""
        if not self._channels:
            return ()
        notification = self._outbox.notification_for_question(question.id)
        if notification is None:
            return ()
        content = self._question_type.render(self._context(question))
        now = self._clock.now()
        return tuple(
            DeliveryTask.new_resolve(
                id=TaskId(new_ulid(self._ids)),
                notification_id=notification.id,
                channel=channel,
                content=content,
                final_state=question.state,
                now=now,
            )
            for channel in self._channels
        )

    def _context(self, question: Question) -> RenderContext:
        resolved = question.state is not QuestionState.OPEN
        return RenderContext(
            title=question.prompt,
            link=self._links.link_for(question.item_id),
            session_label=question.session_label,
            options=() if resolved else question.options,
            final_state=question.state if resolved else None,
            answer_label=question.answer_label,
        )

    def _wake_notifier(self, tasks: Sequence[DeliveryTask]) -> None:
        if tasks and self._outbox_events is not None:
            self._outbox_events.notify()


def _build_options(raw: Sequence[tuple[str, str]]) -> tuple[QuestionOption, ...]:
    """Validate raw `(key, label)` pairs into options (count bounded before any work)."""
    pairs = tuple(raw) if isinstance(raw, Sequence) and not isinstance(raw, str) else None
    if pairs is None or len(pairs) > MAX_OPTIONS:
        raise ValidationError(f"options must be a list of at most {MAX_OPTIONS} (key, label) pairs")
    options: list[QuestionOption] = []
    for pair in pairs:
        if not isinstance(pair, tuple | list) or len(pair) != 2:
            raise ValidationError("each option must be a (key, label) pair")
        key, label = pair
        options.append(QuestionOption(key=key, label=label))
    return tuple(options)
