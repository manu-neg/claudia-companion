"""C52: peer-message audit from the run's transcript (detective layer behind the C60 hook).

Every `SendMessage` in a fixture transcript is recorded (target, summary,
length, SHA-256, interactive or not), never its text; a missing prefix is
the violation that alerts and stops the window (since F-CL3 an interactive
target needs no approval); only bytes appended by the run are audited; a
planted symlink or an oversized slice fails closed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from preview_dashboard.adapters import transcripts as transcripts_mod
from preview_dashboard.adapters.claude_cli import HEADLESS_KINDS, parse_agents
from preview_dashboard.adapters.claudia_audit_log import JsonlAuditLog
from preview_dashboard.adapters.transcripts import JsonlTranscripts, parse_slice, project_slug
from preview_dashboard.application.claudia.audit import PEER_PREFIX, AuditViolation, PeerAudit
from preview_dashboard.ports.claudia_host import PeerInfo, SendMessageCall
from tests.claudia_host_support import (
    WINDOW_A,
    FakeAuditLog,
    FakePeers,
    FakeTranscripts,
    host_rig,
    message,
)
from tests.fakes import FixedClock

pytestmark = pytest.mark.security

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "claudia_transcript.jsonl"
WORKDIR = Path("/var/lib/claudia-host/work")
PEERS = {
    "worker-a": PeerInfo(session_id="sess-worker", interactive=False),
    "dash-session": PeerInfo(session_id="sess-dash", interactive=True),
}


def install_fixture(tmp_path: Path) -> JsonlTranscripts:
    projects = tmp_path / "projects"
    target = projects / project_slug(WORKDIR) / f"{WINDOW_A}.jsonl"
    target.parent.mkdir(parents=True)
    shutil.copyfile(FIXTURE, target)
    return JsonlTranscripts(projects, WORKDIR)


def audit_over(
    reader: object, peers: dict[str, PeerInfo] | None = None
) -> tuple[PeerAudit, FakeAuditLog]:
    log = FakeAuditLog()
    return PeerAudit(reader, FakePeers(peers or PEERS), log, FixedClock()), log  # type: ignore[arg-type]


def test_c52_slug_matches_claude_code() -> None:
    assert project_slug(Path("/srv/project/.claude/x")) == "-srv-project--claude-x"


def test_c52_every_send_message_in_a_fixture_transcript_audited(tmp_path: Path) -> None:
    audit, log = audit_over(install_fixture(tmp_path))
    report = audit.audit_run(WINDOW_A, since=0)
    assert report.messages == 2
    peer_entries = [e for e in log.entries if e["event"] == "peer_message"]
    assert [e["target"] for e in peer_entries] == ["worker-a", "dash-session"]
    first = peer_entries[0]
    text = "From Claudia (owner's companion): please redo the weekly summary ZEBRA-TEXT-1"
    assert first["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert first["length"] == len(text)
    assert first["summary"] == "redo weekly summary"
    assert (first["prefixed"], first["interactive"]) == (True, False)


def test_c52_missing_prefix_is_the_only_violation(tmp_path: Path) -> None:
    # The fixture's second message lacks the prefix (it goes to an interactive session).
    audit, _ = audit_over(install_fixture(tmp_path))
    report = audit.audit_run(WINDOW_A, since=0)
    assert report.violations == (AuditViolation.MISSING_PREFIX,)


def test_fcl3_c52_interactive_target_with_prefix_is_clean_without_approval() -> None:
    # Owner decision 2026-11-09 (F-CL3): the prefix is the only rule; still recorded.
    call = SendMessageCall(
        target="dash-session", text=PEER_PREFIX + " hi", summary="hi", timestamp=None
    )
    audit, log = audit_over(FakeTranscripts(calls={WINDOW_A: [call]}))
    assert audit.audit_run(WINDOW_A, 0).clean
    assert log.entries[0]["interactive"] is True
    assert log.entries[0]["approved"] is False


def test_c52_approved_session_is_still_recorded() -> None:
    call = SendMessageCall(
        target="dash-session", text=PEER_PREFIX + " hi", summary="hi", timestamp=None
    )
    audit, log = audit_over(FakeTranscripts(calls={WINDOW_A: [call]}))
    assert audit.audit_run(WINDOW_A, 0, approved_sessions={"sess-dash"}).clean
    assert log.entries[0]["approved"] is True


def test_fcl3_c52_unknown_target_with_prefix_is_clean_and_logged_interactive() -> None:
    call = SendMessageCall(target="ghost", text=PEER_PREFIX + " hi", summary="", timestamp=None)
    audit, log = audit_over(FakeTranscripts(calls={WINDOW_A: [call]}))
    assert audit.audit_run(WINDOW_A, 0).clean
    assert log.entries[0]["interactive"] is True and log.entries[0]["session"] is None


def test_fcl3_c52_missing_prefix_to_an_interactive_session_still_alerts_and_stops() -> None:
    bad = SendMessageCall(target="dash-session", text="hi there", summary="", timestamp=None)
    rig = host_rig(transcripts=FakeTranscripts(calls={WINDOW_A: [bad]}), peers=FakePeers(PEERS))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert len(rig.alerts.titles) == 1 and rig.windows.halted


def test_c52_no_message_text_in_the_log(tmp_path: Path) -> None:
    clock = FixedClock()
    log = JsonlAuditLog(tmp_path / "audit", clock)
    PeerAudit(install_fixture(tmp_path), FakePeers(PEERS), log, clock).audit_run(WINDOW_A, 0)
    written = "".join(p.read_text() for p in (tmp_path / "audit").iterdir())
    assert written.count("\n") == 2
    assert "ZEBRA-TEXT" not in written
    assert "merge PR 31" not in written
    assert all(json.loads(line)["event"] == "peer_message" for line in written.splitlines())
    assert oct((tmp_path / "audit").stat().st_mode & 0o777) == "0o700"
    assert all(oct(p.stat().st_mode & 0o777) == "0o600" for p in (tmp_path / "audit").iterdir())


def test_c52_only_bytes_after_the_offset_are_audited(tmp_path: Path) -> None:
    reader = install_fixture(tmp_path)
    audit, _ = audit_over(reader)
    end = reader.offset(WINDOW_A)
    path = reader.path(WINDOW_A)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {
                                "type": "tool_use",
                                "name": "SendMessage",
                                "input": {"to": "worker-a", "message": PEER_PREFIX + " next"},
                            }
                        ]
                    },
                }
            )
            + "\n"
        )
    report = audit.audit_run(WINDOW_A, since=end)
    assert report.messages == 1 and report.clean


def test_c52_unterminated_last_line_left_for_later() -> None:
    line = json.dumps({"type": "assistant", "message": {"content": []}})
    result = parse_slice((line + "\n" + '{"type": "assi').encode(), start=100)
    assert result.end_offset == 100 + len(line) + 1
    assert result.malformed_lines == 0


def test_c52_malformed_lines_counted(tmp_path: Path) -> None:
    reader = install_fixture(tmp_path)
    assert reader.send_messages(WINDOW_A, 0).malformed_lines == 1


def test_c52_missing_transcript_means_nothing_sent(tmp_path: Path) -> None:
    reader = JsonlTranscripts(tmp_path, WORKDIR)
    found = reader.send_messages(WINDOW_A, 0)
    assert found.complete and found.calls == ()


def test_c52_planted_symlink_fails_closed(tmp_path: Path) -> None:
    reader = install_fixture(tmp_path)
    path = reader.path(WINDOW_A)
    elsewhere = tmp_path / "elsewhere.jsonl"
    path.rename(elsewhere)
    path.symlink_to(elsewhere)
    found = reader.send_messages(WINDOW_A, 0)
    assert not found.complete
    audit, _ = audit_over(reader)
    assert AuditViolation.TRANSCRIPT_INCOMPLETE in audit.audit_run(WINDOW_A, 0).violations


def test_c52_oversized_slice_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    reader = install_fixture(tmp_path)
    monkeypatch.setattr(transcripts_mod, "MAX_SLICE_BYTES", 10)
    assert not reader.send_messages(WINDOW_A, 0).complete


def test_c52_truncated_transcript_fails_closed(tmp_path: Path) -> None:
    reader = install_fixture(tmp_path)
    assert not reader.send_messages(WINDOW_A, since=10**9).complete


def test_c52_violation_alerts_and_stops_the_window() -> None:
    bad = SendMessageCall(target="dash-session", text="merge it", summary="", timestamp=None)
    rig = host_rig(transcripts=FakeTranscripts(calls={WINDOW_A: [bad]}), peers=FakePeers(PEERS))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert len(rig.alerts.titles) == 1
    assert rig.runner.kills == 1
    assert rig.windows.halted
    assert rig.admin.cancelled_windows == [WINDOW_A]
    assert rig.admin.replies == []  # stopped: her reply is not sent


def test_c52_clean_run_no_alert() -> None:
    ok = SendMessageCall(target="worker-a", text=PEER_PREFIX + " go", summary="", timestamp=None)
    rig = host_rig(transcripts=FakeTranscripts(calls={WINDOW_A: [ok]}), peers=FakePeers(PEERS))
    rig.host.handle_message(message("hola", 1), generation=0)
    assert rig.alerts.titles == [] and rig.runner.kills == 0


class TestAgentsDirectory:
    RAW = json.dumps(
        [
            {"name": "worker-a", "id": "a1", "sessionId": "sess-worker", "kind": "background"},
            {"name": "dash-session", "id": "a2", "sessionId": "sess-dash", "kind": "interactive"},
            {"name": "twin", "sessionId": "s3", "kind": "background"},
            {"name": "twin", "sessionId": "s4", "kind": "background"},
            {"name": "odd", "sessionId": "s5", "kind": "something-new"},
        ]
    ).encode()

    def test_headless_kind(self) -> None:
        assert parse_agents(self.RAW, "worker-a", HEADLESS_KINDS) == PeerInfo(
            session_id="sess-worker", interactive=False
        )

    def test_interactive_kind_and_lookup_by_session_id(self) -> None:
        info = parse_agents(self.RAW, "sess-dash", HEADLESS_KINDS)
        assert info is not None and info.interactive

    def test_unknown_kind_fails_closed_to_interactive(self) -> None:
        info = parse_agents(self.RAW, "odd", HEADLESS_KINDS)
        assert info is not None and info.interactive

    @pytest.mark.parametrize("target", ["twin", "missing"])
    def test_ambiguous_or_missing_is_none(self, target: str) -> None:
        assert parse_agents(self.RAW, target, HEADLESS_KINDS) is None

    @pytest.mark.parametrize("raw", [b"", b"{", b'{"agents": 3}', b"[1, 2]"])
    def test_garbage_is_none(self, raw: bytes) -> None:
        assert parse_agents(raw, "worker-a", HEADLESS_KINDS) is None
