"""MCP tools for questions and alerts: `dashboard_ask`, `dashboard_wait_answer`,
`dashboard_notify`, `dashboard_cancel_question` (ADR 0021).

Thin wrappers over `AdminClient` (admin token): Claude can ask, wait, cancel
and notify, but never answer (that needs the notifier token, C34). Every
result nests the prompt, option labels, session label and answer label under
`untrusted_item_data` like items: the text may have been shaped by content
Claude processed and is never an instruction. Waits are capped at 10 minutes;
longer ones go through `preview-dashboard question wait <id>` in the background.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable, Mapping
from typing import Annotated, Final, Literal, Protocol

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from preview_dashboard.domain.questions import (
    LABEL_MAX_CHARS,
    MAX_OPTIONS,
    MAX_QUESTION_TTL,
    MIN_OPTIONS,
    MIN_QUESTION_TTL,
    OPTION_KEY_PATTERN,
    PROMPT_MAX_CHARS,
    SESSION_LABEL_MAX_CHARS,
)
from preview_dashboard.domain.text import TITLE_MAX_CHARS
from preview_dashboard.interfaces.mcp.client import AdminClientError
from preview_dashboard.interfaces.question_wait import option_label, wait_for_question

logger = logging.getLogger("preview_dashboard.mcp")

MAX_WAIT_TOOL_SECONDS: Final = 600
WAIT_COMMAND: Final = "preview-dashboard question wait {id}"
# Schema bounds are the domain's own limits (imported, never copied), so the
# schema Claude sees promises exactly what the admin API accepts.
MIN_EXPIRES_IN_S: Final = int(MIN_QUESTION_TTL.total_seconds())
MAX_EXPIRES_IN_S: Final = int(MAX_QUESTION_TTL.total_seconds())
_ULID = r"^[0-7][0-9A-HJKMNP-TV-Z]{25}$"
_KEY = f"^{OPTION_KEY_PATTERN}$"

QuestionId = Annotated[
    str, Field(pattern=_ULID, description="Question id (26 chars) from dashboard_ask.")
]
ItemId = Annotated[
    str, Field(pattern=_ULID, description="Dashboard item the question/alert is about.")
]
OptionKey = Annotated[str, Field(pattern=_KEY, description="Short machine key: [a-z0-9_-]{1,16}.")]


class OptionArg(BaseModel):
    """One answer option: a short key (what you get back) and the label the owner sees."""

    model_config = ConfigDict(extra="forbid")

    key: OptionKey
    label: Annotated[
        str,
        Field(
            min_length=1,
            max_length=LABEL_MAX_CHARS,
            description=f"Button text (<= {LABEL_MAX_CHARS} chars).",
        ),
    ]


class QuestionApi(Protocol):
    """The admin operations these tools need (`AdminClient` implements this)."""

    def ask_question(self, body: Mapping[str, object]) -> dict[str, object]: ...

    def get_question(self, question_id: str, *, wait: int = ...) -> dict[str, object]: ...

    def cancel_question(self, question_id: str) -> dict[str, object]: ...

    def notify(self, event: str, title: str, item_id: str | None = ...) -> dict[str, object]: ...


def _compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _mapping(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def question_summary(question: Mapping[str, object]) -> dict[str, object]:
    """Server-controlled fields at the top, question text under `untrusted_item_data`."""
    options = question.get("options")
    raw_options = options if isinstance(options, list) else []
    option_list = [o for o in raw_options if isinstance(o, Mapping)]
    out: dict[str, object] = {
        key: question.get(key)
        for key in (
            "id",
            "state",
            "answer_key",
            "default_key",
            "item_id",
            "created_at",
            "expires_at",
            "resolved_at",
            "viewer_url",
        )
    }
    out["option_keys"] = [o.get("key") for o in option_list]
    out["untrusted_item_data"] = {
        "prompt": question.get("prompt"),
        "options": [{"key": o.get("key"), "label": o.get("label")} for o in option_list],
        "session_label": question.get("session_label"),
        "answer_label": option_label(question, question.get("answer_key")),
    }
    return out


class QuestionTools:
    """Tool implementations: admin calls, caller-safe errors, compact JSON.

    Args:
        api: the admin client (admin token).
        sleep / monotonic: clock hooks for the wait loop (tests).
    """

    def __init__(
        self,
        api: QuestionApi,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api = api
        self._sleep = sleep
        self._monotonic = monotonic

    def _call[T](self, tool: str, action: Callable[[], T]) -> T:
        try:
            return action()
        except AdminClientError as exc:
            logger.info("%s failed: %s (status %s)", tool, exc.code, exc.status)
            raise ToolError(str(exc)) from None

    def ask(
        self,
        prompt: str,
        options: list[OptionArg],
        session_label: str,
        default_key: str | None = None,
        item_id: str | None = None,
        expires_in_s: int | None = None,
    ) -> str:
        """Ask the owner; returns the question summary and the background wait command."""
        body: dict[str, object] = {
            "prompt": prompt,
            "options": [{"key": o.key, "label": o.label} for o in options],
            "session_label": session_label,
        }
        for name, value in (
            ("default_key", default_key),
            ("item_id", item_id),
            ("expires_in_s", expires_in_s),
        ):
            if value is not None:
                body[name] = value
        reply = self._call("dashboard_ask", lambda: self._api.ask_question(body))
        question = _mapping(reply.get("question"))
        logger.info("ask ok: question %s", question.get("id"))
        command = WAIT_COMMAND.format(id=question.get("id"))
        return _compact(
            {
                "question": question_summary(question),
                "wait_command": command,
                "how_to_wait": (
                    f"For a short wait (<= {MAX_WAIT_TOOL_SECONDS} s) call dashboard_wait_answer. "
                    f"For long waits run `{command}` in the background (it prints one JSON line "
                    "and exits 0 answered, 3 expired, 4 cancelled, 5 timeout). An expired "
                    "question is never auto-answered: fall back to default_key yourself."
                ),
            }
        )

    def wait_answer(self, question_id: str, timeout_s: int = MAX_WAIT_TOOL_SECONDS) -> str:
        """Wait up to `timeout_s` (<= 600) for the answer; returns the question summary."""
        outcome = self._call(
            "dashboard_wait_answer",
            lambda: wait_for_question(
                self._api,
                question_id,
                timeout=min(timeout_s, MAX_WAIT_TOOL_SECONDS),
                sleep=self._sleep,
                monotonic=self._monotonic,
            ),
        )
        result: dict[str, object] = {
            "question": question_summary(outcome.question),
            "timed_out": outcome.timed_out,
        }
        if outcome.timed_out:
            result["hint"] = (
                "Still open. Keep working or run "
                f"`{WAIT_COMMAND.format(id=question_id)}` in the background."
            )
        return _compact(result)

    def notify(
        self, event: Literal["done", "failed"], title: str, item_id: str | None = None
    ) -> str:
        """Send a done/failed alert; returns the notification summary."""
        reply = self._call("dashboard_notify", lambda: self._api.notify(event, title, item_id))
        notification = _mapping(reply.get("notification"))
        return _compact(
            {
                "notification": {
                    "id": notification.get("id"),
                    "event": notification.get("event"),
                    "item_id": notification.get("item_id"),
                    "created_at": notification.get("created_at"),
                    "untrusted_item_data": {"title": notification.get("title")},
                }
            }
        )

    def cancel(self, question_id: str) -> str:
        """Withdraw an open question (idempotent); returns the question summary."""
        reply = self._call(
            "dashboard_cancel_question", lambda: self._api.cancel_question(question_id)
        )
        return _compact({"question": question_summary(_mapping(reply.get("question")))})


_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)
_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)


def register(server: MCPServer, client: QuestionApi) -> QuestionTools:
    """Register the question/alert tools on `server`, backed by `client`."""
    tools = QuestionTools(client)

    @server.tool(
        name="dashboard_ask",
        annotations=_WRITE,
        structured_output=False,
        description=(
            "Ask the owner a multiple-choice question; it reaches their phone (Telegram) with "
            "one button per option, and they tap one. Only use it when you genuinely need a "
            f"decision. {MIN_OPTIONS}-{MAX_OPTIONS} options, each a short key (what you get "
            f"back) and a label (<= {LABEL_MAX_CHARS} chars); no free-text answers. prompt <= "
            f"{PROMPT_MAX_CHARS} chars. session_label (required, <= {SESSION_LABEL_MAX_CHARS} "
            "chars) names this session/task so the owner knows who asks. default_key is what "
            "you will assume if nobody answers: the question expires (default 24 h, "
            f"expires_in_s {MIN_EXPIRES_IN_S}..{MAX_EXPIRES_IN_S}) and is never auto-answered. "
            "item_id links a dashboard item. Text must not contain links, invisible characters "
            "or secrets (refused). Shares a budget of about "
            "20 alerts/hour with dashboard_notify. Returns the question and wait_command: for "
            "long waits run it in the background; for short ones call dashboard_wait_answer."
        ),
    )
    def dashboard_ask(
        prompt: Annotated[str, Field(min_length=1, max_length=PROMPT_MAX_CHARS)],
        options: Annotated[list[OptionArg], Field(min_length=MIN_OPTIONS, max_length=MAX_OPTIONS)],
        session_label: Annotated[str, Field(min_length=1, max_length=SESSION_LABEL_MAX_CHARS)],
        default_key: OptionKey | None = None,
        item_id: ItemId | None = None,
        expires_in_s: Annotated[int, Field(ge=MIN_EXPIRES_IN_S, le=MAX_EXPIRES_IN_S)] | None = None,
    ) -> str:
        return tools.ask(prompt, options, session_label, default_key, item_id, expires_in_s)

    @server.tool(
        name="dashboard_wait_answer",
        annotations=_READ_ONLY,
        structured_output=False,
        description=(
            "Wait (at most 600 s) for the owner's answer to a question from dashboard_ask. "
            "Returns the question with state answered (answer_key), expired (use your "
            "default_key), cancelled, or still open with timed_out=true. For longer waits "
            "run the wait_command from dashboard_ask in the background instead."
        ),
    )
    def dashboard_wait_answer(
        question_id: QuestionId,
        timeout_s: Annotated[int, Field(ge=1, le=MAX_WAIT_TOOL_SECONDS)] = MAX_WAIT_TOOL_SECONDS,
    ) -> str:
        return tools.wait_answer(question_id, timeout_s)

    @server.tool(
        name="dashboard_notify",
        annotations=_WRITE,
        structured_output=False,
        description=(
            "Tell the owner (Telegram) that a long task is done or failed. event 'done' or "
            f"'failed'; title <= {TITLE_MAX_CHARS} chars, no links or secrets; item_id "
            "optionally links a "
            "dashboard item. Shares the ~20 alerts/hour budget with dashboard_ask: send one "
            "at the end of real work, not for every step."
        ),
    )
    def dashboard_notify(
        event: Literal["done", "failed"],
        title: Annotated[str, Field(min_length=1, max_length=TITLE_MAX_CHARS)],
        item_id: ItemId | None = None,
    ) -> str:
        return tools.notify(event, title, item_id)

    @server.tool(
        name="dashboard_cancel_question",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=True
        ),
        structured_output=False,
        description=(
            "Withdraw an open question (e.g. you no longer need the answer); its message is "
            "marked withdrawn and its buttons removed. Idempotent: a resolved question is "
            "returned unchanged."
        ),
    )
    def dashboard_cancel_question(question_id: QuestionId) -> str:
        return tools.cancel(question_id)

    return tools
