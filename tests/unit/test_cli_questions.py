"""Tests for the CLI's notification commands: `question wait`, `serve-notifier`, `notify pair|test`.

`question wait` runs end to end against a real admin API on a tmp Unix
socket (answers go through the notifier routes, as in production) and with
a scripted client for every exit code (0 answered, 3 expired, 4 cancelled,
5 timeout, 1 error). `serve-admin` refuses a missing or reused notifier token.
"""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from preview_dashboard.adapters.admin_queue import AdminDeliveryQueue
from preview_dashboard.application import AskCommand
from preview_dashboard.config import Settings
from preview_dashboard.interfaces import cli
from preview_dashboard.interfaces.notifier.commands import NotifierError
from preview_dashboard.interfaces.token_file import TokenGroupPolicy, TokenKind
from tests.admin_support import write_token
from tests.notify_admin_support import (
    LiveNotifyAdmin,
    cli_env,
    live_notify_admin,
    notify_settings,
)

pytestmark = pytest.mark.unit

QID = "01J00000000000000000000001"


def run(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return cli.main(list(argv), out=out), out.getvalue()


@pytest.fixture
def live(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    with live_notify_admin(tmp_path) as admin:
        for key, value in cli_env(admin.settings).items():
            monkeypatch.setenv(key, value)
        yield admin


def _ask(live: LiveNotifyAdmin) -> str:
    question = live.core.questions.ask(
        AskCommand(
            prompt="Ship it?",
            options=[("a", "Yes"), ("b", "No")],
            session_label="cli test",
            default_key="b",
        )
    )
    return question.id


class TestQuestionWaitLive:
    def test_answered_prints_one_line_and_exits_0(self, live):
        qid = _ask(live)

        def answer() -> None:
            time.sleep(0.3)
            queue = AdminDeliveryQueue(live.settings.admin_socket, live.notifier_token.encode())
            try:
                queue.submit_answer(qid, "a", "telegram", "424242")
            finally:
                queue.close()

        threading.Thread(target=answer, daemon=True).start()
        code, output = run("question", "wait", qid, "--timeout", "30s")
        assert code == 0
        assert output.count("\n") == 1
        assert json.loads(output) == {
            "id": qid,
            "state": "answered",
            "answer_key": "a",
            "answer_label": "Yes",
            "default_key": "b",
        }

    def test_cancelled_exits_4(self, live):
        qid = _ask(live)
        live.core.questions.cancel(qid)
        code, output = run("question", "wait", qid)
        assert code == cli.EXIT_CANCELLED == 4
        assert json.loads(output)["state"] == "cancelled"

    def test_timeout_exits_5(self, live):
        qid = _ask(live)
        started = time.monotonic()
        code, output = run("question", "wait", qid, "--timeout", "1")
        assert code == cli.EXIT_TIMEOUT == 5
        assert time.monotonic() - started < 10
        line = json.loads(output)
        assert (line["state"], line["answer_key"], line["default_key"]) == ("open", None, "b")

    def test_unknown_question_exits_1(self, live, capsys):
        code, output = run("question", "wait", "0" * 26, "--timeout", "5s")
        assert code == cli.EXIT_FAILED
        assert output == ""
        err = capsys.readouterr().err
        assert "404" in err
        assert live.admin_token not in err


class _ScriptedClient:
    def __init__(self, replies: list[dict[str, Any]]) -> None:
        self.replies = replies
        self.asked: list[Any] = []

    def __enter__(self) -> _ScriptedClient:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    def get_question(self, question_id: str, *, wait: int = 0) -> dict[str, object]:
        return {"question": self.replies.pop(0)}

    def ask_question(self, body: Any) -> dict[str, object]:
        self.asked.append(body)
        return {"question": {"id": QID, "state": "open"}}


@pytest.fixture
def scripted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    settings = notify_settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)

    def install(*replies: dict[str, Any]) -> _ScriptedClient:
        client = _ScriptedClient(list(replies))
        monkeypatch.setattr(cli, "admin_client", lambda s, a: client)
        return client

    return install


@pytest.mark.parametrize(
    ("state", "code"),
    [("answered", 0), ("expired", 3), ("cancelled", 4), ("bogus", 1)],
)
def test_question_wait_exit_codes(scripted, state, code):
    scripted({"id": QID, "state": state, "answer_key": None, "default_key": "a", "options": []})
    exit_code, output = run("question", "wait", QID)
    assert exit_code == code
    assert json.loads(output)["state"] == state


def test_question_wait_refuses_a_bad_id():
    with pytest.raises(SystemExit) as exited:
        cli.main(["question", "wait", "../items"])
    assert exited.value.code == 2


@pytest.mark.parametrize("timeout", ["0", "1.5h", "9d", "abc"])
def test_question_wait_refuses_a_bad_timeout(timeout):
    with pytest.raises(SystemExit):
        cli.main(["question", "wait", QID, "--timeout", timeout])


def test_question_wait_untrusted_socket_is_an_error(tmp_path, monkeypatch, capsys):
    settings = notify_settings(tmp_path)  # nothing listens on its socket
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    assert run("question", "wait", QID)[0] == cli.EXIT_FAILED
    assert "question wait failed" in capsys.readouterr().err


def test_notify_test_asks_through_the_admin_api(live):
    code, output = run("notify", "test")
    assert code == 0
    line = json.loads(output)
    assert line["state"] == "open"
    assert line["wait_command"] == f"preview-dashboard question wait {line['id']}"
    question = live.core.questions.get(line["id"])
    assert [o.key for o in question.options] == ["yes", "no"]


def test_notify_test_admin_down_is_one_line(tmp_path, monkeypatch, capsys):
    settings = notify_settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    assert run("notify", "test")[0] == cli.EXIT_FAILED
    err = capsys.readouterr().err
    assert "notify test failed" in err
    assert "Traceback" not in err


def test_serve_notifier_wiring(tmp_path, monkeypatch):
    settings = notify_settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    calls: list[tuple[Settings, TokenGroupPolicy]] = []

    def fake(config: Settings, *, token_groups: TokenGroupPolicy) -> int:
        calls.append((config, token_groups))
        return 0

    monkeypatch.setattr(cli, "run_notifier", fake)
    assert run("serve-notifier", "--token-group", "0")[0] == 0
    [(config, groups)] = calls
    assert config == settings
    # The notifier's own token is telegram.token; a plain group stays shared.
    assert groups.own is TokenKind.TELEGRAM and groups.shared == frozenset({0})


def test_serve_notifier_startup_error_is_one_line(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_settings", lambda: notify_settings(tmp_path))

    def fail(config: Settings, *, token_groups: TokenGroupPolicy) -> int:
        raise NotifierError("notifications are disabled (notify_enabled = false)")

    monkeypatch.setattr(cli, "run_notifier", fail)
    assert run("serve-notifier")[0] == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert "refusing to start: notifications are disabled" in err
    assert "Traceback" not in err


def test_notify_pair_wiring(tmp_path, monkeypatch):
    settings = notify_settings(tmp_path)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    seen: list[Path] = []

    def fake(path: Path, out: Any, *, token_groups: TokenGroupPolicy) -> int:
        assert token_groups.own is TokenKind.TELEGRAM
        seen.append(path)
        out.write("paired\n")
        return 0

    monkeypatch.setattr(cli, "pair", fake)
    assert run("notify", "pair") == (0, "paired\n")
    assert seen == [settings.telegram_token_file]


class TestServeAdminNotifierToken:
    def test_missing_notifier_token_refuses(self, tmp_path, monkeypatch, capsys):
        settings = notify_settings(tmp_path)
        write_token(settings.admin_token_file)
        monkeypatch.setattr(cli, "load_settings", lambda: settings)
        assert run("serve-admin")[0] == cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert "notifier token file" in err

    def test_notifier_token_equal_to_admin_token_refuses(self, tmp_path, monkeypatch, capsys):
        settings = notify_settings(tmp_path)
        token = write_token(settings.admin_token_file)
        write_token(settings.notifier_token_file, token)
        monkeypatch.setattr(cli, "load_settings", lambda: settings)
        assert run("serve-admin")[0] == cli.EXIT_FAILED
        assert "must differ" in capsys.readouterr().err

    def test_disabled_notifications_need_no_notifier_token(self, tmp_path, monkeypatch):
        settings = notify_settings(tmp_path, notify_enabled=False)
        write_token(settings.admin_token_file)
        monkeypatch.setattr(cli, "load_settings", lambda: settings)
        served: list[Any] = []
        monkeypatch.setattr(
            "preview_dashboard.interfaces.admin.server.serve",
            lambda app, path, allowed_peer_uids=(): served.append(allowed_peer_uids),
        )
        assert run("serve-admin", "--allowed-peer-uid", "0", "--notifier-peer-uid", "7")[0] == 0
        assert served == [(0, 7)]


def test_check_config_reports_the_notifier_token(tmp_path, monkeypatch):
    settings = notify_settings(tmp_path)
    write_token(settings.admin_token_file)
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    code, output = run("check-config")
    report = json.loads(output)
    assert code == cli.EXIT_FAILED
    assert report["notify_enabled"] is True
    assert report["notify_owner_chat_id_set"] is True
    assert "notifier token file" in report["notifier_credentials_file"]
    write_token(settings.notifier_token_file)
    code, output = run("check-config")
    assert code == 0
    assert json.loads(output)["notifier_credentials_file"] == "ok"
