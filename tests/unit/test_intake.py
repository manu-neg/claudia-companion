"""Unit tests for MCP intake: naming (relpaths), reading, limits, and helpers.

Covers `IntakePolicy.collect` happy paths and bundle naming rules, the
chunked reader, limit errors, relpath diagnostics (`relpaths.py`), the
`DenyList` matcher semantics, and `safe_display`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from preview_dashboard.config import DEFAULT_INTAKE_DENIED_PATTERNS
from preview_dashboard.interfaces.mcp.denylist import DenyList
from preview_dashboard.interfaces.mcp.errors import IntakeError, IntakeErrorCode, safe_display
from preview_dashboard.interfaces.mcp.intake import IntakeLimits, IntakePolicy
from preview_dashboard.interfaces.mcp.relpaths import check_relpath, explain_relpath_error
from tests.intake_support import clean_env, make_policy, read_all

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("clean_env")]
__all__ = ["clean_env"]  # fixture re-export (keeps ruff from flagging the import)


@pytest.fixture
def outbox(tmp_path: Path) -> Path:
    root = tmp_path / "outbox"
    root.mkdir()
    return root


def _write(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# --- naming -------------------------------------------------------------


def test_single_file_keeps_basename(outbox: Path) -> None:
    f = _write(outbox / "sub" / "report.html", b"<p>hi</p>")
    with make_policy(outbox).collect([str(f)]) as bundle:
        assert [x.relpath for x in bundle.files] == ["report.html"]
        assert bundle.files[0].size == 9
        assert bundle.total_bytes == 9
        assert read_all(bundle) == {"report.html": b"<p>hi</p>"}


def test_directory_is_relative_to_itself_and_sorted(outbox: Path) -> None:
    site = outbox / "site"
    _write(site / "index.html", b"i")
    _write(site / "css" / "app.css", b"c")
    _write(site / "b.js", b"b")
    with make_policy(outbox).collect([str(site)]) as bundle:
        assert [x.relpath for x in bundle.files] == ["b.js", "css/app.css", "index.html"]
        assert read_all(bundle)["css/app.css"] == b"c"


def test_multiple_files_without_base_use_basenames(outbox: Path) -> None:
    a = _write(outbox / "x" / "a.txt")
    b = _write(outbox / "y" / "b.txt")
    with make_policy(outbox).collect([str(a), str(b)]) as bundle:
        assert [x.relpath for x in bundle.files] == ["a.txt", "b.txt"]


def test_base_names_files_relative_to_base(outbox: Path) -> None:
    site = outbox / "site"
    index = _write(site / "index.html")
    _write(site / "css" / "app.css")
    with make_policy(outbox).collect([str(index), str(site / "css")], base=str(site)) as bundle:
        assert [x.relpath for x in bundle.files] == ["index.html", "css/app.css"]


def test_base_equal_to_directory(outbox: Path) -> None:
    site = outbox / "site"
    _write(site / "a.txt")
    with make_policy(outbox).collect([str(site)], base=str(site)) as bundle:
        assert [x.relpath for x in bundle.files] == ["a.txt"]


def test_path_not_under_base_rejected(outbox: Path) -> None:
    a = _write(outbox / "a.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(a)], base=str(outbox / "other"))
    assert exc.value.code is IntakeErrorCode.INVALID_REQUEST


def test_allowed_root_itself_can_be_published(outbox: Path) -> None:
    _write(outbox / "a.txt")
    with make_policy(outbox).collect([str(outbox)]) as bundle:
        assert [x.relpath for x in bundle.files] == ["a.txt"]


def test_trailing_slash_and_dot_segments_are_normalized(outbox: Path) -> None:
    _write(outbox / "d" / "a.txt")
    with make_policy(outbox).collect([f"{outbox}/./d/"]) as bundle:
        assert [x.relpath for x in bundle.files] == ["a.txt"]


def test_duplicate_names_rejected(outbox: Path) -> None:
    a = _write(outbox / "x" / "a.txt")
    b = _write(outbox / "y" / "a.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(a), str(b)])
    assert exc.value.code is IntakeErrorCode.DUPLICATE


def test_case_only_duplicates_rejected(outbox: Path) -> None:
    a = _write(outbox / "x" / "A.txt")
    b = _write(outbox / "y" / "a.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(a), str(b)])
    assert exc.value.code is IntakeErrorCode.DUPLICATE


def test_empty_directory_rejected(outbox: Path) -> None:
    (outbox / "empty" / "nested").mkdir(parents=True)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(outbox / "empty")])
    assert exc.value.code is IntakeErrorCode.EMPTY


def test_zero_byte_file_ok(outbox: Path) -> None:
    f = _write(outbox / "empty.txt", b"")
    with make_policy(outbox).collect([str(f)]) as bundle:
        assert read_all(bundle) == {"empty.txt": b""}


# --- request validation --------------------------------------------------


@pytest.mark.parametrize(
    "paths",
    [
        [],
        "relative/string",
        ["relative.txt"],
        [""],
        ["/a/\x00b"],
        ["/a/../b"],
        [b"/bytes/path"],
    ],
)
def test_invalid_requests(outbox: Path, paths: object) -> None:
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect(paths)  # type: ignore[arg-type]
    assert exc.value.code is IntakeErrorCode.INVALID_REQUEST


def test_missing_file(outbox: Path) -> None:
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(outbox / "nope.txt")])
    assert exc.value.code is IntakeErrorCode.NOT_FOUND
    assert "nope.txt" in str(exc.value)


def test_missing_root(tmp_path: Path) -> None:
    root = tmp_path / "not-created"
    with pytest.raises(IntakeError) as exc:
        make_policy(root).collect([str(root / "a.txt")])
    assert exc.value.code is IntakeErrorCode.NOT_FOUND


def test_intermediate_file_is_not_a_directory(outbox: Path) -> None:
    _write(outbox / "a.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(outbox / "a.txt" / "b.txt")])
    assert exc.value.code is IntakeErrorCode.NOT_FOUND


def test_policy_constructor_validation() -> None:
    limits = IntakeLimits(max_files=1, max_file_bytes=1, max_item_bytes=1)
    deny = DenyList(())
    with pytest.raises(ValueError, match="at least one"):
        IntakePolicy(allowed_roots=(), denylist=deny, limits=limits)
    with pytest.raises(ValueError, match="absolute"):
        IntakePolicy(allowed_roots=("rel",), denylist=deny, limits=limits)
    with pytest.raises(ValueError, match="> 0"):
        IntakeLimits(max_files=0, max_file_bytes=1, max_item_bytes=1)


# --- reader --------------------------------------------------------------


def test_reader_can_read_twice_and_respects_chunk_size(outbox: Path) -> None:
    f = _write(outbox / "a.bin", bytes(range(10)))
    with make_policy(outbox).collect([str(f)]) as bundle:
        item = bundle.files[0]
        with item.open_reader(chunk_size=4) as chunks:
            parts = list(chunks)
        assert [len(p) for p in parts] == [4, 4, 2]
        with item.open_reader() as chunks:
            assert b"".join(chunks) == bytes(range(10))
        with pytest.raises(ValueError, match="chunk_size"), item.open_reader(chunk_size=0):
            pass


def test_reader_after_close_raises(outbox: Path) -> None:
    f = _write(outbox / "a.txt")
    bundle = make_policy(outbox).collect([str(f)])
    bundle.close()
    bundle.close()  # idempotent
    assert bundle.closed
    with pytest.raises(RuntimeError, match="closed"), bundle.files[0].open_reader():
        pass


def test_reader_detects_shrink(outbox: Path) -> None:
    f = _write(outbox / "a.txt", b"0123456789")
    with make_policy(outbox).collect([str(f)]) as bundle:
        os.truncate(f, 3)
        with (
            pytest.raises(IntakeError) as exc,
            bundle.files[0].open_reader(chunk_size=2) as chunks,
        ):
            b"".join(chunks)
    assert exc.value.code is IntakeErrorCode.CHANGED
    assert "shrank" in str(exc.value)


# --- limits --------------------------------------------------------------


def test_max_files(outbox: Path) -> None:
    for i in range(3):
        _write(outbox / "d" / f"{i}.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_files=2).collect([str(outbox / "d")])
    assert exc.value.code is IntakeErrorCode.LIMIT


def test_max_files_counts_requested_paths(outbox: Path) -> None:
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_files=1).collect([str(outbox / "a"), str(outbox / "b")])
    assert exc.value.code is IntakeErrorCode.LIMIT


def test_max_file_bytes(outbox: Path) -> None:
    f = _write(outbox / "big.bin", b"x" * 11)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_file_bytes=10, max_item_bytes=100).collect([str(f)])
    assert exc.value.code is IntakeErrorCode.LIMIT
    assert "big.bin" in str(exc.value)


def test_max_file_bytes_boundary_ok(outbox: Path) -> None:
    f = _write(outbox / "ok.bin", b"x" * 10)
    policy = make_policy(outbox, max_file_bytes=10, max_item_bytes=100)
    with policy.collect([str(f)]) as bundle:
        assert bundle.total_bytes == 10


def test_max_item_bytes(outbox: Path) -> None:
    _write(outbox / "d" / "a.bin", b"x" * 8)
    _write(outbox / "d" / "b.bin", b"x" * 8)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_file_bytes=10, max_item_bytes=15).collect([str(outbox / "d")])
    assert exc.value.code is IntakeErrorCode.LIMIT


def test_too_many_directories(outbox: Path) -> None:
    for i in range(3):
        (outbox / "d" / f"sub{i}").mkdir(parents=True)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_files=2).collect([str(outbox / "d")])
    assert exc.value.code is IntakeErrorCode.LIMIT


def test_huge_directory_listing_aborts(outbox: Path) -> None:
    for i in range(5):
        _write(outbox / "d" / f"{i}.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox, max_files=2).collect([str(outbox / "d")])
    assert exc.value.code is IntakeErrorCode.LIMIT


def test_too_deep_tree(outbox: Path) -> None:
    deep = outbox / "d" / Path(*[f"l{i}" for i in range(17)])
    _write(deep / "a.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(outbox / "d")])
    assert exc.value.code is IntakeErrorCode.RELPATH
    assert "16 segments" in str(exc.value)


# --- relpath diagnostics ------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("100%.txt", "U+0025 PERCENT SIGN"),
        ("Brand\u2122.txt", "U+2122 TRADE MARK SIGN"),
        ("price\u00a5.txt", "U+00A5 YEN SIGN"),
        ("\uff71.txt", "U+FF71 HALFWIDTH KATAKANA LETTER A"),
        ("a:b.txt", "U+003A COLON"),
        ("CON.txt", "reserved device name"),
        ("name.", "must not end with a dot"),
        (" lead.txt", "leading or trailing whitespace"),
    ],
)
def test_relpath_errors_explain_rule(outbox: Path, name: str, expected: str) -> None:
    f = _write(outbox / name)
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(f)])
    assert exc.value.code is IntakeErrorCode.RELPATH
    message = str(exc.value)
    assert expected in message
    assert "Rename" in message
    assert "never renamed automatically" in message


def test_relpath_nfkc_hint() -> None:
    message = explain_relpath_error("Brand\u2122.txt")
    assert message is not None
    assert "compatibility character" in message


def test_relpath_nfd_name_explained(outbox: Path) -> None:
    f = _write(outbox / "re\u0301sume\u0301.txt")
    with pytest.raises(IntakeError) as exc:
        make_policy(outbox).collect([str(f)])
    assert exc.value.code is IntakeErrorCode.RELPATH
    assert "NFC" in str(exc.value)


def test_relpath_invisible_char_is_escaped_in_message() -> None:
    message = explain_relpath_error("evil\u202etxt.exe")
    assert message is not None
    assert "\u202e" not in message
    assert "\\u202e" in message
    assert "U+202E" in message


def test_check_relpath_valid_is_identity() -> None:
    assert check_relpath("dir/file.txt") == "dir/file.txt"
    assert explain_relpath_error("ok.txt") is None


def test_relpath_whole_path_rule() -> None:
    message = explain_relpath_error("a" * 300)
    assert message is not None
    assert "segment" in message


# --- DenyList semantics --------------------------------------------------


def test_denylist_whole_component_glob() -> None:
    deny = DenyList(["id_*"])
    assert deny.match(["home", "id_rsa"]) == "id_*"
    assert deny.match(["home", "xid_rsa"]) is None


def test_denylist_case_and_nfc_insensitive() -> None:
    deny = DenyList(["Caf\u00e9*"])
    assert deny.match(["CAFE\u0301.txt"]) == "caf\u00e9*"


def test_denylist_full_pattern_needs_consecutive_components() -> None:
    deny = DenyList([".config/gh"])
    assert deny.match([".config", "gh", "hosts.yml"]) == ".config/gh"
    assert deny.match([".config", "x", "gh"]) is None
    assert deny.match(["gh"]) is None
    assert deny.match_last([]) is None


def test_default_denylist_catches_samples() -> None:
    deny = DenyList(DEFAULT_INTAKE_DENIED_PATTERNS)
    for parts in (
        ["x", "ID_ED25519"],
        [".ENV"],
        ["a", ".Git", "config"],
        ["Login Data"],
        ["db.sqlite3"],
        ["my-secret.txt"],
        [".bash_history"],
    ):
        assert deny.match(parts) is not None, parts
    assert deny.match(["docs", "report.html"]) is None


def test_safe_display_escapes_and_truncates() -> None:
    assert safe_display("a\x00b\\c\u200bd") == "a\\u0000b\\u005cc\\u200bd"
    assert safe_display("\U000e0041") == "\\U000e0041"
    assert safe_display("x" * 400).endswith("...")


@pytest.mark.parametrize(
    "parts",
    [
        ["putty", "server.ppk"],
        ["keys", "AuthKey_ABC.p8"],
        ["gcp", "my-service-account.json"],
        ["gcp", "prod_ServiceAccount_key.json"],
        ["oauth", "token.json"],
        ["home", ".dockercfg"],
        ["home", ".s3cfg"],
        ["home", ".boto"],
        ["home", ".terraformrc"],
        ["appdata", "terraform.rc"],
        ["x", "rclone.conf"],
        ["home", ".config", "rclone", "anything.txt"],
        ["home", ".gitconfig"],
        ["home", ".config", "op", "config"],
        ["etc", "ssh", "ssh_host_ed25519_key"],
        ["etc", "ssh", "ssh_host_rsa_key.pub"],
        ["etc", "shadow-"],
        ["etc", "gshadow-"],
        ["etc", "sudoers.d"],
    ],
)
def test_denylist_follow_up_patterns(parts: list[str]) -> None:
    deny = DenyList(DEFAULT_INTAKE_DENIED_PATTERNS)
    assert deny.match(parts) is not None, parts


def test_safe_display_escapes_single_quote() -> None:
    assert safe_display("it's") == "it\\'s"
