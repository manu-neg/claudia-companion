"""Ports of the Claudia host (units M4b, M5b): runs, transcripts, peers, audit, alerts, admin
calls, approvals, the hook gate's run lifecycle, KB commits and voice replies.

The host's application services (`application/claudia/`) depend only on
these protocols; `adapters/claude_cli.py`, `adapters/transcripts.py` and
`adapters/claudia_admin_client.py` implement them, `interfaces/claudia/`
wires them (C49-C52, C58). Value types carry no secrets: run requests hold
the prompt only in memory (it goes to the child's stdin, never argv or logs).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from preview_dashboard.domain.approvals import (
    ActionKind,
    ApprovalId,
    ApprovalKind,
    ApprovalRequest,
    WindowId,
)
from preview_dashboard.domain.errors import InvalidStateError
from preview_dashboard.domain.owner_messages import OwnerMessage, OwnerMessageId

# Env var the runner sets in a run's child env and the `claudia-kb` MCP server reads: the
# per-run nonce that ties `request_approval` to the run in progress (F-CL3b, C46).
RUN_NONCE_ENV: Final = "CLAUDIA_RUN_NONCE"


class RunRefusedError(InvalidStateError):
    """A run must not start (settings/hook check failed, C50, C59); the message names the rule."""


@dataclass(frozen=True, slots=True, kw_only=True)
class RunRequest:
    """One `claude -p` turn the host wants to run (argv built from a fixed template, C51).

    Attributes:
        window_id: the host-generated session UUID (never taken from text).
        resume: False for the first turn of a window (`--session-id`), else `--resume`.
        prompt: the user turn, written to stdin only.
        allowed_tools / disallowed_tools: the host's tool set for this turn.
        builtin_tools: the exact built-in tools that exist in the run (`--tools`);
            empty = none (fail closed, C51).
        generation: the host's `/stop` generation the turn belongs to; the runner
            refuses to spawn it once a newer stop epoch was seen (C58).
        persona: the checked, framed persona block (F-CL2) or "" for none; the
            runner appends it after the fixed host rules, never before.
        run_nonce: random per-run token (hex) the runner puts in the child env as
            `RUN_NONCE_ENV`; "" = none (recap). Never logged or in the repr.
    """

    window_id: WindowId
    resume: bool
    prompt: str
    allowed_tools: tuple[str, ...]
    disallowed_tools: tuple[str, ...]
    # The window-close recap: the runner uses the host's recap MCP config
    # (`claudia-kb --caller recap`) instead of the normal one (unit M5b).
    recap: bool = False
    builtin_tools: tuple[str, ...] = ()
    generation: int = 0
    persona: str = ""
    run_nonce: str = ""

    def __repr__(self) -> str:
        # The prompt is owner text: never in reprs or logs (C29).
        return (
            f"RunRequest(window_id={self.window_id!r}, resume={self.resume}, "
            f"recap={self.recap}, generation={self.generation})"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RunOutcome:
    """What one run produced (parsed from `--output-format json`).

    Attributes:
        result_text: her final answer (reply candidate; never logged), or None.
        permission_denials: count of `permission_denials` (C55 input for M5).
        killed: ended by `/stop` (no reply is sent).
        timed_out: ended by the host's run timeout.
        credential_expires_at: subscription expiry if the output reported one (`/status`).
    """

    exit_code: int | None
    result_text: str | None = None
    is_error: bool = False
    permission_denials: int = 0
    killed: bool = False
    timed_out: bool = False
    credential_expires_at: str | None = None

    def __repr__(self) -> str:
        return (
            f"RunOutcome(exit_code={self.exit_code!r}, is_error={self.is_error}, "
            f"denials={self.permission_denials}, killed={self.killed}, "
            f"timed_out={self.timed_out})"
        )


class ClaudeRunner(Protocol):
    """Runs Claudia's turns as child processes, each in its own process group (C51, C58)."""

    def run(self, request: RunRequest) -> RunOutcome:
        """Run one turn to completion (blocking); never raises for a failed run."""
        ...

    def kill_all(self, *, epoch: int | None = None) -> int:
        """Kill every process group this runner started (`/stop`); return how many.

        `epoch`: the new `/stop` generation; from now on a request with an older
        `generation` is refused before it spawns (closes the check-then-spawn race).
        """
        ...

    def busy(self) -> bool:
        """True while a run, or a process left in a run's group (dispatched work), is alive."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class SendMessageCall:
    """One `SendMessage` tool call found in a transcript (C52). `text` stays in memory only."""

    target: str
    text: str
    summary: str
    timestamp: str | None

    def __repr__(self) -> str:
        return f"SendMessageCall(target={self.target!r}, length={len(self.text)})"


@dataclass(frozen=True, slots=True, kw_only=True)
class TranscriptSlice:
    """The `SendMessage` calls appended to a window's transcript since an offset."""

    calls: tuple[SendMessageCall, ...]
    end_offset: int
    malformed_lines: int = 0
    # A truncated or unreadable transcript can't prove nothing was sent.
    complete: bool = True


class TranscriptReader(Protocol):
    """Reads the JSONL transcript Claude Code writes for a window (not the model, C52)."""

    def offset(self, window_id: WindowId) -> int:
        """Current size of the window's transcript (0 if none yet)."""
        ...

    def send_messages(self, window_id: WindowId, since: int) -> TranscriptSlice:
        """`SendMessage` calls written after byte `since` (bounded; never raises)."""
        ...


@dataclass(frozen=True, slots=True, kw_only=True)
class PeerInfo:
    """A live session as `claude agents --json` reports it (V5)."""

    session_id: str
    interactive: bool


class PeerDirectory(Protocol):
    """Resolves a `SendMessage` target to a session; unknown -> None (treated interactive)."""

    def lookup(self, target: str) -> PeerInfo | None:
        """The session a message target names, or None (fail closed)."""
        ...


AuditValue = str | int | bool | None


class AuditLog(Protocol):
    """Append-only record of peer messages, approvals and denials (no message text, C52)."""

    def record(self, entry: Mapping[str, AuditValue]) -> None:
        """Append one entry; never raises (a failure is logged by type name)."""
        ...


class HostAlerts(Protocol):
    """Sends the host's fixed `failed` alerts (titles are fixed host text, never model output)."""

    def failed(self, title: str) -> None:
        """Send one failed alert; never raises."""
        ...


class RunPreflight(Protocol):
    """Checks run before every Claudia run (settings sources, hooks; C50, C59)."""

    def check(self) -> None:
        """Return if a run may start.

        Raises:
            RunRefusedError: a settings source disables or overrides the hooks,
                or the host settings file changed.
        """
        ...


class WindowIds(Protocol):
    """Generates window session ids (canonical lowercase UUIDs, C51)."""

    def new_window_id(self) -> WindowId:
        """A fresh, never-reused window id."""
        ...


class HostAdmin(Protocol):
    """The host's calls on the admin API (`claudia` token, `/v1/claudia/*`, C45)."""

    def unhandled(self, wait: float) -> Sequence[OwnerMessage]:
        """Unhandled inbox messages (long-poll up to `wait` s)."""
        ...

    def mark_handled(self, message_id: OwnerMessageId) -> bool:
        """Claim a message (CAS); False if it was already handled (C58: processed once)."""
        ...

    def send_reply(self, text: str, *, message_id: OwnerMessageId | None) -> bool:
        """Queue a reply; False if the admin refused it (scan, budget)."""
        ...

    def cancel_open_approvals(self, window_id: WindowId) -> Sequence[str]:
        """Cancel every open approval request of `window_id` (`/stop`, C58); return their ids."""
        ...

    def cancel_all_open_approvals(self) -> Sequence[str]:
        """Cancel every open approval request of every window; return their ids.

        For host start and `/stop` (F-CL3b): requests that outlive a restart or
        a closed window would otherwise hold the open cap for 24 h.
        """
        ...

    def report_health(self, screen: str) -> None:
        """Report screen health (`ok` | `degraded` | `down`)."""
        ...


# --- unit M5b: approval flow, hook gate, KB commits, voice ------------------------------


class ApprovalAdmin(Protocol):
    """The host's approval calls on the admin API (C46): create PENDING, wait, consume, cancel.

    There is deliberately no tap, code or approve call: only the owner (via
    the notifier token + TOTP) moves a request to APPROVED.
    """

    def request_approval(
        self,
        *,
        window_id: WindowId,
        kind: ApprovalKind,
        action_text: str | None,
        action_kind: ActionKind | None,
        action_target: str | None,
        message_id: OwnerMessageId | None,
    ) -> ApprovalRequest:
        """Create a PENDING request (its Approve/Deny prompt is queued by the admin).

        Raises:
            ConflictError: the window already has an open request.
            ValidationError: the admin refused the text, target or ids (incl. secret scan).
            StorageUnavailableError: the admin is unreachable or failed.
        """
        ...

    def get_approval(self, approval_id: ApprovalId, wait: float = 0) -> ApprovalRequest:
        """The request as stored, held up to `wait` s while PENDING/TAPPED.

        Raises:
            StorageUnavailableError: the admin is unreachable, failed or answered badly.
        """
        ...

    def consume_approval(self, approval_id: ApprovalId) -> tuple[str, ApprovalRequest | None]:
        """APPROVED -> CONSUMED once: `(result, request)` (`consumed` on success).

        Raises:
            StorageUnavailableError: the admin is unreachable, failed or answered badly.
        """
        ...

    def cancel_approval(self, approval_id: ApprovalId) -> str:
        """Close one open request; returns the admin's cancel result code.

        Raises:
            StorageUnavailableError: the admin is unreachable, failed or answered badly.
        """
        ...


class RunGate(Protocol):
    """The C59/C60 hook gate's run lifecycle (`HookGate`): covers live exactly one run."""

    def begin_run(
        self,
        window_id: WindowId,
        covers: Iterable[ApprovalRequest] = (),
        *,
        carry_over: bool = False,
    ) -> None:
        """Start a run of `window_id` holding these CONSUMED approvals.

        `carry_over`: the covers were asked in an earlier, since closed window (F-CL3).

        Raises:
            ValidationError: a cover is not CONSUMED, or of another window
                without `carry_over`.
        """
        ...

    def end_run(self) -> None:
        """End the run in progress (its covers end with it)."""
        ...


class KbCommits(Protocol):
    """Commits the KB changes of a run (`KbService.commit_run`, C53)."""

    def commit_run(self, message: str) -> str | None:
        """One commit of everything changed; None if nothing changed."""
        ...

    def restore_worktree(self) -> None:
        """Put the notes back to the last commit after a failed `commit_run` (F-C2c).

        Runs under the KB's cross-process locks (fixcheck-a-2).

        Raises:
            KbBusyError: another process held the KB locks for the whole wait.
            StorageUnavailableError: git failed or no work tree is configured.
        """
        ...

    def worktree_clean(self) -> bool:
        """True if no note differs from the last commit (`/new` clears a KB halt only then).

        Raises:
            KbBusyError: another process held the KB locks for the whole wait.
            StorageUnavailableError: git failed or no work tree is configured.
        """
        ...


class KbWorktree(Protocol):
    """Restores and checks the KB work tree, `*.md` only (`GitKbHistory`)."""

    def restore_worktree(self) -> None:
        """Check out every tracked note from HEAD and delete untracked notes.

        Raises:
            StorageUnavailableError: git failed.
        """
        ...

    def worktree_clean(self) -> bool:
        """True if `git status --porcelain -- *.md` is empty.

        Raises:
            StorageUnavailableError: git failed.
        """
        ...


class HaltFlag(Protocol):
    """The persisted KB halt (newcode-1): survives a host restart until `/new` clears it."""

    def is_set(self) -> bool:
        """True if the flag is set, or its state can't be read (fail closed)."""
        ...

    def set(self) -> None:
        """Persist the halt.

        Raises:
            StorageUnavailableError: it could not be written (the caller stays halted).
        """
        ...

    def clear(self) -> None:
        """Remove the halt.

        Raises:
            StorageUnavailableError: it could not be removed (the caller stays halted).
        """
        ...


class VoiceReplies(Protocol):
    """Posts a reply with its voice note (`POST /v1/claudia/voice`, same budget, C56)."""

    def send_voice(self, text: str, audio: bytes, *, message_id: OwnerMessageId | None) -> bool:
        """Queue text + audio; False if the admin refused it (scan, caps, budget)."""
        ...
