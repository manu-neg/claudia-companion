"""Tests for the MCP question/alert tools (`interfaces/mcp/tools/questions.py`).

The real `MCPServer` driven by the SDK's in-process client; the tools call a
real admin API on a tmp Unix socket with the admin token. Answers are
submitted the only way possible, through the notifier routes with the
notifier token (`AdminDeliveryQueue`). Question text must come back nested
under `untrusted_item_data`, never at the top level.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
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
from preview_dashboard.interfaces.mcp.client import AdminClient
from preview_dashboard.interfaces.mcp.server import DashboardTools, build_server
from preview_dashboard.interfaces.mcp.tools.questions import (
    MAX_WAIT_TOOL_SECONDS,
    QuestionTools,
    question_summary,
)
from tests.notify_admin_support import LiveNotifyAdmin, live_notify_admin

pytestmark = pytest.mark.unit

MARKER = "Pick-the-DB-7Q"
OPTIONS = [{"key": "a", "label": "SQLite"}, {"key": "b", "label": "Postgres"}]


@pytest.fixture
def live(tmp_path: Path) -> Iterator[LiveNotifyAdmin]:
    with live_notify_admin(tmp_path, notify_rate_per_hour=100) as admin:
        yield admin


@pytest.fixture
def server(live: LiveNotifyAdmin, tmp_path: Path) -> Iterator[MCPServer]:
    from preview_dashboard.interfaces.mcp.intake import IntakePolicy

    outbox = tmp_path / "outbox"
    outbox.mkdir(exist_ok=True)
    with AdminClient.from_settings(live.settings) as http:
        intake = IntakePolicy.from_settings(live.settings)
        yield build_server(DashboardTools(intake=intake, admin=http), questions=http)


def _text(result: Any) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


async def _ok(client: Client, tool: str, **args: Any) -> Any:
    result = await client.call_tool(tool, args)
    assert not result.is_error, _text(result)
    return json.loads(_text(result))


async def _err(client: Client, tool: str, **args: Any) -> str:
    result = await client.call_tool(tool, args)
    assert result.is_error
    text = _text(result)
    assert "Traceback" not in text
    return text


def _answer_later(live: LiveNotifyAdmin, question_id: str, key: str, delay: float) -> None:
    def run() -> None:
        time.sleep(delay)
        queue = AdminDeliveryQueue(live.settings.admin_socket, live.notifier_token.encode())
        try:
            queue.submit_answer(question_id, key, "telegram", "424242")
        finally:
            queue.close()

    threading.Thread(target=run, daemon=True).start()


async def test_question_tools_are_registered(server: MCPServer) -> None:
    async with Client(server) as mcp:
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    assert {
        "dashboard_ask",
        "dashboard_wait_answer",
        "dashboard_notify",
        "dashboard_cancel_question",
    } <= set(tools)
    ask_schema = tools["dashboard_ask"].input_schema
    assert set(ask_schema["required"]) == {"prompt", "options", "session_label"}
    # There is no answer tool: Claude can never answer its own questions (C34).
    assert not any("answer" in name and name != "dashboard_wait_answer" for name in tools)


def _bounds(schema: dict[str, Any]) -> dict[str, Any]:
    """The constraint keywords of a property, looking through `anyOf: [T, null]`."""
    variants: list[dict[str, Any]] = schema.get("anyOf", [schema])
    for variant in variants:
        if variant.get("type") != "null":
            return variant
    raise AssertionError(schema)


async def test_schema_bounds_equal_the_domain_limits(server: MCPServer) -> None:
    # Claude sees the real limits: nothing the schema allows is refused by
    # the admin API for length/count/range, and nothing it refuses is valid.
    async with Client(server) as mcp:
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    ask = tools["dashboard_ask"].input_schema
    props = ask["properties"]
    assert _bounds(props["prompt"])["maxLength"] == PROMPT_MAX_CHARS
    session = _bounds(props["session_label"])
    assert (session["minLength"], session["maxLength"]) == (1, SESSION_LABEL_MAX_CHARS)
    assert "session_label" in ask["required"]
    options = _bounds(props["options"])
    assert (options["minItems"], options["maxItems"]) == (MIN_OPTIONS, MAX_OPTIONS)
    option = ask["$defs"]["OptionArg"]["properties"]
    assert option["label"]["maxLength"] == LABEL_MAX_CHARS
    key_pattern = f"^{OPTION_KEY_PATTERN}$"
    assert option["key"]["pattern"] == key_pattern
    assert _bounds(props["default_key"])["pattern"] == key_pattern
    expires = _bounds(props["expires_in_s"])
    assert (expires["minimum"], expires["maximum"]) == (
        MIN_QUESTION_TTL.total_seconds(),
        MAX_QUESTION_TTL.total_seconds(),
    )
    title = _bounds(tools["dashboard_notify"].input_schema["properties"]["title"])
    assert title["maxLength"] == TITLE_MAX_CHARS
    wait = _bounds(tools["dashboard_wait_answer"].input_schema["properties"]["timeout_s"])
    assert wait["maximum"] == MAX_WAIT_TOOL_SECONDS


async def test_ask_nests_question_text_as_untrusted(server: MCPServer) -> None:
    async with Client(server) as mcp:
        result = await _ok(
            mcp,
            "dashboard_ask",
            prompt=f"Which database? {MARKER}",
            options=OPTIONS,
            session_label="db task",
            default_key="a",
            expires_in_s=600,
        )
    question = result["question"]
    top_level = {k: v for k, v in question.items() if k != "untrusted_item_data"}
    assert MARKER not in json.dumps(top_level)
    assert "SQLite" not in json.dumps(top_level)
    untrusted = question["untrusted_item_data"]
    assert MARKER in untrusted["prompt"]
    assert untrusted["options"] == OPTIONS
    assert untrusted["session_label"] == "db task"
    assert question["option_keys"] == ["a", "b"]
    assert (question["state"], question["default_key"]) == ("open", "a")
    assert result["wait_command"] == f"preview-dashboard question wait {question['id']}"
    assert "background" in result["how_to_wait"]


async def test_wait_answer_returns_the_owner_choice(
    server: MCPServer, live: LiveNotifyAdmin
) -> None:
    async with Client(server) as mcp:
        asked = await _ok(
            mcp, "dashboard_ask", prompt="Ship it?", options=OPTIONS, session_label="t"
        )
        qid = asked["question"]["id"]
        _answer_later(live, qid, "b", delay=0.3)
        waited = await _ok(mcp, "dashboard_wait_answer", question_id=qid, timeout_s=20)
    assert waited["timed_out"] is False
    question = waited["question"]
    assert (question["state"], question["answer_key"]) == ("answered", "b")
    assert question["untrusted_item_data"]["answer_label"] == "Postgres"


async def test_wait_answer_times_out_with_a_hint(server: MCPServer) -> None:
    async with Client(server) as mcp:
        asked = await _ok(
            mcp, "dashboard_ask", prompt="Ship it?", options=OPTIONS, session_label="t"
        )
        qid = asked["question"]["id"]
        waited = await _ok(mcp, "dashboard_wait_answer", question_id=qid, timeout_s=1)
    assert waited["timed_out"] is True
    assert waited["question"]["state"] == "open"
    assert f"question wait {qid}" in waited["hint"]


async def test_cancel_and_notify(server: MCPServer, live: LiveNotifyAdmin) -> None:
    async with Client(server) as mcp:
        asked = await _ok(
            mcp, "dashboard_ask", prompt="Ship it?", options=OPTIONS, session_label="t"
        )
        qid = asked["question"]["id"]
        cancelled = await _ok(mcp, "dashboard_cancel_question", question_id=qid)
        assert cancelled["question"]["state"] == "cancelled"
        again = await _ok(mcp, "dashboard_cancel_question", question_id=qid)
        assert again["question"]["state"] == "cancelled"
        sent = await _ok(mcp, "dashboard_notify", event="done", title=f"Built {MARKER}")
    notification = sent["notification"]
    assert notification["event"] == "done"
    assert MARKER not in json.dumps(
        {k: v for k, v in notification.items() if k != "untrusted_item_data"}
    )
    assert MARKER in notification["untrusted_item_data"]["title"]
    kinds = [t.payload.question_id is None for t in live.core.outbox.pending(20)]
    assert True in kinds  # the done alert was queued


@pytest.mark.parametrize(
    "args",
    [
        {"prompt": "x", "options": OPTIONS},  # session_label required
        {"prompt": "x", "options": OPTIONS[:1], "session_label": "t"},
        {"prompt": "x", "options": [{"key": "A B", "label": "x"}] * 2, "session_label": "t"},
        {"prompt": "x", "options": [{**OPTIONS[0], "extra": 1}, OPTIONS[1]], "session_label": "t"},
        {"prompt": "x", "options": OPTIONS, "session_label": "t", "expires_in_s": 10},
        {"prompt": "x", "options": OPTIONS, "session_label": "t", "item_id": "../x"},
        # One past each domain limit is refused by the schema already.
        {"prompt": "x" * (PROMPT_MAX_CHARS + 1), "options": OPTIONS, "session_label": "t"},
        {"prompt": "x", "options": OPTIONS, "session_label": "t" * (SESSION_LABEL_MAX_CHARS + 1)},
        {
            "prompt": "x",
            "options": [{"key": "a", "label": "x" * (LABEL_MAX_CHARS + 1)}, OPTIONS[1]],
            "session_label": "t",
        },
        {
            "prompt": "x",
            "options": [{"key": f"k{i}", "label": "x"} for i in range(MAX_OPTIONS + 1)],
            "session_label": "t",
        },
    ],
)
async def test_ask_argument_validation(server: MCPServer, args: dict[str, Any]) -> None:
    async with Client(server) as mcp:
        await _err(mcp, "dashboard_ask", **args)


async def test_admin_errors_are_clean_tool_errors(server: MCPServer) -> None:
    async with Client(server) as mcp:
        missing = await _err(mcp, "dashboard_wait_answer", question_id="0" * 26, timeout_s=5)
        assert "404" in missing
        bad = await _err(
            mcp,
            "dashboard_ask",
            prompt="x",
            options=[{"key": "a", "label": "A"}, {"key": "a", "label": "B"}],
            session_label="t",
        )
        assert "400" in bad
        await _err(mcp, "dashboard_notify", event="question", title="x")
        await _err(
            mcp, "dashboard_wait_answer", question_id="01J0000000000000000000000Z", timeout_s=601
        )


def test_question_summary_tolerates_junk() -> None:
    summary = question_summary({"id": "x", "options": "junk", "prompt": 5})
    assert summary["option_keys"] == []
    assert summary["untrusted_item_data"] == {
        "prompt": 5,
        "options": [],
        "session_label": None,
        "answer_label": None,
    }


def test_wait_answer_caps_the_timeout() -> None:
    seen: list[float] = []

    class Api:
        def get_question(self, question_id: str, *, wait: int = 0) -> dict[str, object]:
            seen.append(wait)
            return {"question": {"id": question_id, "state": "cancelled", "options": []}}

        def ask_question(self, body: Any) -> dict[str, object]:
            raise AssertionError

        def cancel_question(self, question_id: str) -> dict[str, object]:
            raise AssertionError

        def notify(self, event: str, title: str, item_id: str | None = None) -> dict[str, object]:
            raise AssertionError

    tools = QuestionTools(Api())
    result = json.loads(tools.wait_answer("01J00000000000000000000001", timeout_s=10_000))
    assert result["question"]["state"] == "cancelled"
    assert seen == [60]
