"""Claudia windows (C58, plan D2): idle 3 h / cap 8 h / never while busy, with a fake clock.

Covers `WindowTracker`, the exact-match host commands, and the host's
window handling (recap turn with the recap tool set, no recap after
`/stop`, `/new`, `/voice`, `/status` health only).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from preview_dashboard.application.claudia.runs import (
    TOOL_SETS,
    VOICE_UNAVAILABLE_TEXT,
    ToolSetName,
)
from preview_dashboard.application.claudia.windows import (
    CloseReason,
    HostCommand,
    Window,
    WindowPolicy,
    WindowTracker,
    parse_host_command,
)
from tests.claudia_host_support import (
    WINDOW_A,
    WINDOW_B,
    SeqWindowIds,
    fake_voice,
    host_rig,
    message,
)
from tests.fakes import FixedClock

pytestmark = pytest.mark.unit


def tracker() -> tuple[WindowTracker, FixedClock]:
    clock = FixedClock()
    return WindowTracker(clock, SeqWindowIds()), clock


def opened(windows: WindowTracker, generation: int = 0) -> Window:
    window = windows.for_message(generation)
    assert window is not None
    return window


class TestTracker:
    def test_no_window_until_a_message(self) -> None:
        windows, _ = tracker()
        assert windows.current is None
        assert windows.due(busy=False) is None

    def test_message_opens_one_window_and_reuses_it(self) -> None:
        windows, clock = tracker()
        first = opened(windows)
        clock.advance(timedelta(minutes=5))
        second = opened(windows)
        assert first.id == second.id == WINDOW_A
        assert second.last_message_at == clock.now()
        assert second.opened_at == first.opened_at

    def test_idle_closes_after_three_hours(self) -> None:
        windows, clock = tracker()
        opened(windows)
        clock.advance(timedelta(hours=3) - timedelta(seconds=1))
        assert windows.due(busy=False) is None
        clock.advance(timedelta(seconds=1))
        assert windows.due(busy=False) is CloseReason.IDLE

    def test_hard_cap_at_eight_hours_despite_activity(self) -> None:
        windows, clock = tracker()
        opened(windows)
        for _ in range(16):
            clock.advance(timedelta(minutes=30))
            opened(windows)
        assert windows.due(busy=False) is CloseReason.CAP

    @pytest.mark.parametrize("hours", [3, 8, 24])
    def test_never_closes_while_busy(self, hours: int) -> None:
        windows, clock = tracker()
        opened(windows)
        clock.advance(timedelta(hours=hours))
        assert windows.due(busy=True) is None
        assert windows.due(busy=False) is not None

    def test_close_then_next_message_opens_a_fresh_window(self) -> None:
        windows, _ = tracker()
        opened(windows)
        assert windows.close() is not None
        assert opened(windows).id == WINDOW_B

    def test_halt_until_next_message(self) -> None:
        windows, _ = tracker()
        opened(windows)
        windows.halt(1)
        assert windows.halted
        opened(windows, generation=1)
        assert not windows.halted

    def test_message_queued_before_the_stop_keeps_the_halt(self) -> None:
        """host-flow-2: a message queued under an older generation never clears a halt."""
        windows, clock = tracker()
        first = opened(windows)
        windows.halt(1)
        clock.advance(timedelta(minutes=1))
        assert windows.for_message(0) is None
        assert windows.halted
        current = windows.current
        assert current is not None and current.last_message_at == first.last_message_at
        assert opened(windows, generation=1).id == WINDOW_A
        assert not windows.halted

    def test_stale_message_opens_no_window(self) -> None:
        windows, _ = tracker()
        windows.halt(2)
        assert windows.for_message(1) is None
        assert windows.current is None

    def test_voice_toggle(self) -> None:
        windows, _ = tracker()
        assert windows.toggle_voice() is None
        opened(windows)
        assert windows.toggle_voice() is True
        assert windows.toggle_voice() is False

    def test_mark_started_only_for_the_current_window(self) -> None:
        windows, _ = tracker()
        opened(windows)
        windows.mark_started(WINDOW_B)
        assert windows.current is not None and not windows.current.started
        windows.mark_started(WINDOW_A)
        assert windows.current is not None and windows.current.started

    @pytest.mark.parametrize(
        ("idle", "cap"),
        [(timedelta(0), timedelta(hours=1)), (timedelta(hours=2), timedelta(hours=1))],
    )
    def test_policy_validation(self, idle: timedelta, cap: timedelta) -> None:
        with pytest.raises(ValueError, match="idle"):
            WindowPolicy(idle=idle, cap=cap)


class TestCommands:
    @pytest.mark.parametrize("command", list(HostCommand))
    def test_exact_match(self, command: HostCommand) -> None:
        assert parse_host_command(command.value) is command

    @pytest.mark.parametrize(
        "text", ["/stop ", " /stop", "/STOP", "/stop now", "/stop\n", "stop", "/stop@claudia_bot"]
    )
    def test_anything_else_is_a_message(self, text: str) -> None:
        assert parse_host_command(text) is None


class TestHostWindows:
    def test_first_turn_creates_the_session_then_resumes(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.host.handle_message(message("dos", 2), generation=0)
        first, second = rig.runner.requests
        assert (first.window_id, first.resume) == (WINDOW_A, False)
        assert (second.window_id, second.resume) == (WINDOW_A, True)

    def test_idle_window_gets_a_recap_then_a_fresh_window(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.clock.advance(timedelta(hours=3))
        rig.host.handle_message(message("dos", 2), generation=0)
        _, recap, fresh = rig.runner.requests
        assert recap.window_id == WINDOW_A and recap.resume
        assert recap.allowed_tools == TOOL_SETS[ToolSetName.RECAP].allowed
        assert "closing (idle)" in recap.prompt
        assert (fresh.window_id, fresh.resume) == (WINDOW_B, False)

    def test_tick_closes_a_due_window(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.clock.advance(timedelta(hours=8))
        rig.host.tick()
        assert rig.windows.current is None
        assert len(rig.runner.requests) == 2

    def test_tick_keeps_a_busy_window(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.runner.is_busy = True
        rig.clock.advance(timedelta(hours=9))
        rig.host.tick()
        assert rig.windows.current is not None
        assert len(rig.runner.requests) == 1

    def test_no_recap_run_while_halted(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.host.stop()
        rig.clock.advance(timedelta(hours=3))
        rig.host.tick()
        assert rig.windows.current is None
        assert len(rig.runner.requests) == 1  # no recap: no new run after /stop

    def test_new_closes_early_with_recap(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.host.command(HostCommand.NEW, message("/new", 2).id)
        assert rig.windows.current is None
        assert "closing (new)" in rig.runner.requests[-1].prompt

    def test_voice_toggle_replies_fixed_text(self) -> None:
        rig = host_rig(voice=fake_voice())
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.host.command(HostCommand.VOICE, message("/voice", 2).id)
        assert rig.admin.replies[-1][0] == "Voice replies: on."

    def test_voice_without_models_says_so_and_does_not_toggle(self) -> None:
        rig = host_rig()
        rig.host.handle_message(message("uno", 1), generation=0)
        rig.host.command(HostCommand.VOICE, message("/voice", 2).id)
        assert rig.admin.replies[-1][0] == VOICE_UNAVAILABLE_TEXT
        assert rig.windows.current is not None and not rig.windows.current.voice

    def test_status_lists_no_open_approval(self) -> None:
        rig = host_rig()
        assert "approvals open: none" in rig.host.status_text()

    def test_status_is_health_only(self) -> None:
        rig = host_rig()
        owner_text = "please summarise the zebra-unicorn report"
        rig.host.handle_message(message(owner_text, 1), generation=0)
        rig.clock.advance(timedelta(minutes=65))
        text = rig.host.status_text()
        assert "open 1h05m" in text
        assert "screen: ok" in text
        assert "zebra" not in text
