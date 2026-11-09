"""Unit tests for `domain/shell_lex.py`: words, quoting, operators, substitutions, heredocs."""

from __future__ import annotations

import pytest

from preview_dashboard.domain.shell_lex import (
    Op,
    ShellSyntaxError,
    Word,
    lex,
    parse_script,
)

pytestmark = pytest.mark.unit


def texts(src: str) -> list[list[str]]:
    return [[w.text for w in c.words] for c in parse_script(src)]


def test_words_and_quotes() -> None:
    assert texts("a 'b c' \"d $x\" e\\ f") == [["a", "b c", "d $x", "e f"]]


def test_operators_split_commands() -> None:
    assert texts("a; b && c || d | e & f\ng") == [["a"], ["b"], ["c"], ["d"], ["e"], ["f"], ["g"]]


def test_pipe_marks_stdin() -> None:
    first, second = parse_script("a | b")
    assert not first.stdin_fed
    assert second.stdin_fed


def test_redirections_leave_the_words() -> None:
    (cmd,) = parse_script("a 2>/dev/null >out <in x")
    assert [w.text for w in cmd.words] == ["a", "x"]
    assert [op for op, _ in cmd.redirects] == [">", ">", "<"]
    assert cmd.stdin_fed


def test_flags_on_words() -> None:
    tokens, _ = lex("$x 'lit' *.py ~/a {a,b} $'\\x41' \"q\"")
    words = [t for t in tokens if isinstance(t, Word)]
    assert [w.dynamic for w in words] == [True, False, False, False, False, True, False]
    assert [w.pattern for w in words] == [False, False, True, True, True, False, False]
    assert [w.quoted for w in words] == [False, True, False, False, False, True, True]


def test_redirect_targets_keep_their_flags() -> None:
    # The classifier treats a non-literal write target as maybe-protected (hook-4).
    (cmd,) = parse_script('echo x > ~/a >> $HOME/b 2>&1 > "c"')
    targets = {w.text: w.literal for _, w in cmd.redirects}
    assert targets == {"~/a": False, "$HOME/b": False, "1": True, "c": True}


def test_substitutions_are_lexed() -> None:
    assert texts('echo $(rm a) `rm b` <(rm c) "$(rm d)"')[1:] == [
        ["rm", "a"],
        ["rm", "b"],
        ["rm", "c"],
        ["rm", "d"],
    ]


def test_nested_substitution() -> None:
    assert ["rm", "x"] in texts("echo $(echo $(rm x))")


def test_heredoc_body_is_data_unless_it_expands() -> None:
    assert texts("cat <<'EOF'\n$(rm x)\nEOF\nls") == [["cat"], ["ls"]]
    assert ["rm", "x"] in texts("cat <<EOF\n$(rm x)\nEOF")
    assert texts("cat <<-EOF\n\tbody\n\tEOF") == [["cat"]]


def test_heredoc_inside_substitution() -> None:
    src = "git commit -m \"$(cat <<'EOF'\nmsg (with) 'quotes\nEOF\n)\" && ls"
    assert texts(src) == [["git", "commit", "-m", src[15:-7]], ["ls"], ["cat"]]


def test_comments_and_continuations() -> None:
    assert texts("a # rm x\nb \\\nc") == [["a"], ["b", "c"]]
    assert texts("a#b") == [["a#b"]]


def test_operator_tokens() -> None:
    tokens, _ = lex("a&&b")
    assert tokens == [Word("a"), Op("&&"), Word("b")]


@pytest.mark.parametrize(
    "src",
    ["'a", '"a', "$(a", "`a", "${a", "a \\", "cat <<E\nx", "a >", "x\x00", "$'a"],
)
def test_unreadable_raises(src: str) -> None:
    with pytest.raises(ShellSyntaxError):
        parse_script(src)


def test_depth_and_length_limits() -> None:
    with pytest.raises(ShellSyntaxError):
        parse_script("$(" * 20 + ")" * 20)
    with pytest.raises(ShellSyntaxError):
        parse_script("a" * (256 * 1024 + 1))
