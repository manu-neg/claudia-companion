"""Unit tests for the KB MCP tool bodies, frontmatter parsing and bundled prompts."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from preview_dashboard.adapters.kb_store import FsKbStore
from preview_dashboard.adapters.secret_scan import RegexSecretScanner
from preview_dashboard.application.claudia.kb import (
    KbService,
    NoteKind,
    classify,
    load_prompt,
    parse_sources,
    split_frontmatter,
)
from preview_dashboard.interfaces.claudia.kb_mcp import KbTools, build_server


@pytest.fixture
def tools(tmp_path: Path) -> KbTools:
    root = tmp_path / "kb"
    root.mkdir()
    return KbTools(KbService(FsKbStore(root), RegexSecretScanner()), "claudia")


def test_tools_round_trip(tools: KbTools) -> None:
    assert tools.write("now.md", "hello\n").startswith("written now.md")
    assert tools.read("now.md") == "hello\n"
    tools.write("topics/c/_topic.md", "t\n")
    assert tools.delete("topics/c/_topic.md") == "deleted topics/c/_topic.md"


def test_tool_errors_become_tool_errors(tools: KbTools) -> None:
    with pytest.raises(ToolError, match="read-only"):
        tools.write("persona.md", "x\n")
    with pytest.raises(ToolError, match="read-only"):
        tools.delete("persona.md")
    with pytest.raises(ToolError, match="no such note"):
        tools.read("topics/c/n.md")
    with pytest.raises(ToolError, match="layout"):
        tools.read("../etc/passwd")
    aws = "AKIA" + "IOSFODNN7EXAMPLE"  # split: the file itself stays scan-clean
    with pytest.raises(ToolError) as ei:
        tools.write("now.md", aws + "\n")
    assert aws not in str(ei.value)


def test_server_registers_exactly_three_tools(tools: KbTools) -> None:
    server = build_server(tools)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"kb_read", "kb_write", "kb_delete"}


def test_classify_kinds() -> None:
    assert classify("topics/a/_topic.md") is NoteKind.TOPIC
    assert classify("topics/a/b.md") is NoteKind.NOTE
    assert classify("topics/work-log/2026-01.md") is NoteKind.WORKLOG
    assert classify("journal/2026-01-02-x.md") is NoteKind.JOURNAL


def test_frontmatter_and_sources() -> None:
    front, body = split_frontmatter("---\nsources: [a@1, 'b@2']\n---\nbody")
    assert front is not None
    assert body == "body"
    assert parse_sources(front) == ["a@1", "b@2"]
    assert split_frontmatter("no front")[0] is None
    assert split_frontmatter("---\nunterminated\n")[0] is None


def test_bundled_prompts_load_without_header_comment() -> None:
    recap = load_prompt("recap.md")
    assert recap.startswith("The conversation window is closing")
    assert "persona.md" in recap
    assert load_prompt("seed/persona.md").startswith("# Claudia")
