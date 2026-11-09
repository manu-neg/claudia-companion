"""deploy/lib/notify_config.py — notifier keys in an existing config.toml.

Used by deploy/install.sh (stdlib only, runs under the host's python3 >= 3.11):
`check` / `ensure` add `notify_enabled = true` and `notify_owner_chat_id` when
absent, keeping the file's owner and mode; `enabled [--key K]` reports the
file's `notify_enabled` (default) or `claudia_enabled` flag.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFLICT = 3

_ENABLED_FALSE_LINE = re.compile(r"^(\s*notify_enabled\s*=\s*)false(\s*(#.*)?)$")
_TABLE_HEADER = re.compile(r"^\s*\[")


class ConfigEditError(Exception):
    """The file can't be edited safely; the operator must edit it by hand."""


class ChatIdConflictError(ConfigEditError):
    """The file already names a different owner chat id (never overwritten, C34)."""


@dataclass(frozen=True, slots=True)
class Plan:
    """What `ensure` would change; `new_text is None` means nothing to do."""

    actions: tuple[str, ...]
    new_text: str | None


def _read_regular_file(path: Path) -> str:
    # lstat, not stat: a symlinked config could point anywhere (C16).
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ConfigEditError(f"{path} is not a regular file")
    return path.read_text(encoding="utf-8")


def _parse(text: str, path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigEditError(f"{path} is not valid TOML ({exc})") from None


def plan_edit(text: str, chat_id: int, path: Path) -> Plan:
    """Plan the minimal edit that enables notifications for `chat_id`.

    Raises:
        ChatIdConflictError: a different `notify_owner_chat_id` is already set.
        ConfigEditError: unparseable file, odd value types, or an edit that
            wouldn't round-trip to exactly the intended settings.
    """
    data = _parse(text, path)
    current_chat = data.get("notify_owner_chat_id")
    current_enabled = data.get("notify_enabled")
    # type() not isinstance(): TOML `true` is a bool, and bool subclasses int.
    if current_chat is not None and type(current_chat) is not int:
        raise ConfigEditError(f"{path}: notify_owner_chat_id is not an integer")
    if current_chat is not None and current_chat != chat_id:
        raise ChatIdConflictError(
            f"{path} already has notify_owner_chat_id = {current_chat}, not {chat_id}; "
            "edit it by hand if the owner's chat changed"
        )
    if current_enabled is not None and type(current_enabled) is not bool:
        raise ConfigEditError(f"{path}: notify_enabled is not a boolean")
    if current_enabled is True and current_chat is not None:
        return Plan(actions=(), new_text=None)

    lines = text.splitlines(keepends=True)
    actions: list[str] = []
    if current_enabled is False:
        lines, flipped = _flip_enabled(lines)
        if not flipped:
            raise ConfigEditError(f"{path}: can't locate the notify_enabled = false line")
        actions.append("set notify_enabled = true")
    added: list[str] = []
    if current_enabled is None:
        added.append("notify_enabled = true\n")
        actions.append("add notify_enabled = true")
    if current_chat is None:
        added.append(f"notify_owner_chat_id = {chat_id}\n")
        actions.append(f"add notify_owner_chat_id = {chat_id}")
    if added:
        lines = _insert_top_level(lines, added)
    new_text = "".join(lines)

    # Round-trip check: the result must be exactly the old settings plus ours.
    expected = {**data, "notify_enabled": True, "notify_owner_chat_id": chat_id}
    if _parse(new_text, path) != expected:
        raise ConfigEditError(f"{path}: the edit would not round-trip; edit it by hand")
    return Plan(actions=tuple(actions), new_text=new_text)


def _flip_enabled(lines: list[str]) -> tuple[list[str], bool]:
    out = list(lines)
    for i, line in enumerate(out):
        if _TABLE_HEADER.match(line):
            break  # top-level keys only ever precede the first table header
        body = line.rstrip("\r\n")
        match = _ENABLED_FALSE_LINE.match(body)
        if match:
            out[i] = f"{match.group(1)}true{match.group(2)}{line[len(body) :]}"
            return out, True
    return out, False


def _insert_top_level(lines: list[str], added: list[str]) -> list[str]:
    block = ["# --- added by deploy/install.sh --telegram-chat-id (ADR 0023) ---\n", *added]
    for i, line in enumerate(lines):
        if _TABLE_HEADER.match(line):
            # Before the first [table], or the keys would land inside it.
            return [*lines[:i], *block, "\n", *lines[i:]]
    head = list(lines)
    if head and not head[-1].endswith("\n"):
        head[-1] += "\n"
    return [*head, "\n", *block]


def write_preserving(path: Path, text: str) -> None:
    """Atomically replace `path` with `text`, keeping its owner, group and mode."""
    info = os.lstat(path)
    fd, tmp = tempfile.mkstemp(prefix=".config.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            if (info.st_uid, info.st_gid) != (os.geteuid(), os.getegid()):
                os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _chat_id(value: str) -> int:
    if not (value.isascii() and value.isdigit()) or int(value) <= 0:
        raise argparse.ArgumentTypeError("chat id must be a positive integer")
    return int(value)


def _cmd_plan(args: argparse.Namespace, *, apply: bool) -> int:
    path: Path = args.config
    plan = plan_edit(_read_regular_file(path), args.chat_id, path)
    if not apply:
        return EXIT_OK  # `check`: a preflight, silent unless it refuses
    if plan.new_text is None:
        print(f"  {path} already enables the notifier for chat id {args.chat_id}")
        return EXIT_OK
    for action in plan.actions:
        print(f"+ edit {path}: {action}")
    if not args.dry_run:
        write_preserving(path, plan.new_text)
    return EXIT_OK


def _cmd_enabled(args: argparse.Namespace) -> int:
    path: Path = args.config
    if not path.exists():
        print("false")
        return EXIT_OK
    # Only a real TOML `true` counts: anything else is "off" (fail closed).
    value = _parse(_read_regular_file(path), path).get(args.key, False)
    print("true" if value is True else "false")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code (3 = chat id conflict)."""
    parser = argparse.ArgumentParser(prog="notify_config.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "ensure"):
        cmd = sub.add_parser(name)
        cmd.add_argument("config", type=Path)
        cmd.add_argument("chat_id", type=_chat_id)
        cmd.add_argument("--dry-run", action="store_true")
    enabled = sub.add_parser("enabled")
    enabled.add_argument("config", type=Path)
    # claudia_enabled: install.sh --claudia enables the host only when it is on (M9).
    enabled.add_argument(
        "--key", choices=("notify_enabled", "claudia_enabled"), default="notify_enabled"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "enabled":
            return _cmd_enabled(args)
        return _cmd_plan(args, apply=args.command == "ensure")
    except ChatIdConflictError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFLICT
    except (ConfigEditError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
