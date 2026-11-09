"""A small, strict POSIX/bash command lexer for the risky-action classifier (C59).

`parse_script` turns a Bash tool command into flat `SimpleCommand`s: words
after quote removal (flagged when an expansion, glob, brace or tilde makes
their value unknowable), redirections and stdin source. Every command
substitution (`$(…)`, backticks, `<(…)`, `>(…)`) and expanding heredoc body
is lexed recursively and its commands are returned too, so nothing hides
inside them. Anything it cannot read for sure raises `ShellSyntaxError`:
the classifier treats that as risky kind `unknown` (fail closed). Pure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from preview_dashboard.domain.errors import ValidationError

MAX_SCRIPT_CHARS: Final = 256 * 1024
MAX_DEPTH: Final = 16

# Longest first, so `&&` wins over `&` and `<<-` over `<<`.
_OPERATORS: Final = (
    ";;&",
    "&>>",
    "<<-",
    "<<<",
    ";;",
    ";&",
    "&&",
    "||",
    "|&",
    ">>",
    ">|",
    "<>",
    "<<",
    ">&",
    "<&",
    "&>",
    ";",
    "&",
    "|",
    "(",
    ")",
    "<",
    ">",
)
_OP_START: Final = frozenset(op[0] for op in _OPERATORS)
SEPARATORS: Final = frozenset({";", ";;", ";&", ";;&", "&", "&&", "||", "(", ")", "\n"})
PIPES: Final = frozenset({"|", "|&"})
REDIRECTS: Final = frozenset({"<", ">", ">>", ">|", "<>", "&>", "&>>", ">&", "<&", "<<<"})
HEREDOCS: Final = frozenset({"<<", "<<-"})
OUTPUT_REDIRECTS: Final = frozenset({">", ">>", ">|", "<>", "&>", "&>>", ">&"})
_GLOB_CHARS: Final = frozenset("*?[")
_BLANKS: Final = frozenset(" \t")


class ShellSyntaxError(ValidationError):
    """The command cannot be read for sure (bad quoting, too deep, too long)."""


@dataclass(frozen=True, slots=True)
class Word:
    """One shell word after quote removal.

    Attributes:
        text: the literal value (expansions kept as their source text).
        dynamic: its value depends on an expansion (`$x`, `$(…)`, `$'…'`).
        pattern: an unquoted glob, brace or leading tilde may expand it.
        quoted: some part of it was quoted or escaped.
    """

    text: str
    dynamic: bool = False
    pattern: bool = False
    quoted: bool = False

    @property
    def literal(self) -> bool:
        """True if `text` is exactly what the shell passes on."""
        return not (self.dynamic or self.pattern)


@dataclass(frozen=True, slots=True)
class Op:
    """One operator token (`;`, `&&`, `|`, `>`, newline as `\\n`, ...)."""

    text: str


Token = Word | Op


@dataclass(frozen=True, slots=True)
class SimpleCommand:
    """One simple command: its words, redirections and where stdin comes from."""

    words: tuple[Word, ...]
    redirects: tuple[tuple[str, Word], ...] = ()
    stdin_fed: bool = False


@dataclass(slots=True)
class _Pending:
    delimiter: str
    strip_tabs: bool
    expands: bool


@dataclass(slots=True)
class _WordBuf:
    parts: list[str] = field(default_factory=list)
    dynamic: bool = False
    pattern: bool = False
    quoted: bool = False
    started: bool = False

    def add(self, text: str, *, quoted: bool = False) -> None:
        self.parts.append(text)
        self.started = True
        self.quoted = self.quoted or quoted

    def take(self) -> Word | None:
        if not self.started:
            return None
        word = Word("".join(self.parts), self.dynamic, self.pattern, self.quoted)
        self.parts = []
        self.dynamic = self.pattern = self.quoted = self.started = False
        return word


class _Lexer:
    """Lexes `src[pos:]`; in paren mode stops at the `)` that closes `$(`."""

    def __init__(self, src: str, pos: int, depth: int, *, paren: bool) -> None:
        if depth > MAX_DEPTH:
            raise ShellSyntaxError("command nests too deeply")
        self.src = src
        self.pos = pos
        self.depth = depth
        self.paren = paren
        self.tokens: list[Token] = []
        self.nested: list[list[Token]] = []
        self._pending: list[_Pending] = []
        self._open_parens = 0

    # --- driver -------------------------------------------------------------------

    def run(self) -> int:
        buf = _WordBuf()
        src = self.src
        while self.pos < len(src):
            ch = src[self.pos]
            if ch in _BLANKS:
                self._end_word(buf)
                self.pos += 1
            elif ch == "\n":
                self._end_word(buf)
                self.tokens.append(Op("\n"))
                self.pos += 1
                self._read_heredoc_bodies()
            elif ch == "#" and not buf.started:
                while self.pos < len(src) and src[self.pos] != "\n":
                    self.pos += 1
            elif ch == "\\":
                self._backslash(buf)
            elif ch == "'":
                buf.add(self._single_quoted(), quoted=True)
            elif ch == '"':
                self.pos += 1
                buf.add(self._double_quoted(buf, closing=True), quoted=True)
            elif ch == "$":
                self._dollar(buf)
            elif ch == "`":
                self._backtick(buf)
            elif ch in "<>" and self._peek(1) == "(":
                # Process substitution: a word whose value is a /dev/fd path.
                self.pos += 2
                self._substitution(buf)
            elif ch in _OP_START:
                if self._operator(buf):
                    return self.pos
            else:
                # This char itself is unquoted, so it globs even in a partly quoted word.
                if self._is_pattern_char(ch, buf):
                    buf.pattern = True
                buf.add(ch)
                self.pos += 1
        self._end_word(buf)
        if self.paren:
            raise ShellSyntaxError("unterminated command substitution")
        if self._pending:
            raise ShellSyntaxError("unterminated heredoc")
        return self.pos

    def _peek(self, offset: int) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def _is_pattern_char(self, ch: str, buf: _WordBuf) -> bool:
        if ch in _GLOB_CHARS or ch == "{":
            return True
        # Tilde expansion only at the start of a word (or after `=`/`:` in assignments).
        after_sep = bool(buf.parts) and buf.parts[-1].endswith(("=", ":"))
        return ch == "~" and (not buf.started or after_sep)

    def _end_word(self, buf: _WordBuf) -> None:
        word = buf.take()
        if word is not None:
            self._emit_word(word)

    def _emit_word(self, word: Word) -> None:
        last = self.tokens[-1] if self.tokens else None
        if isinstance(last, Op) and last.text in HEREDOCS:
            # Heredoc delimiter: a quoted one stops expansion of the body.
            self._pending.append(_Pending(word.text, last.text == "<<-", expands=not word.quoted))
        self.tokens.append(word)

    # --- quoting --------------------------------------------------------------------

    def _backslash(self, buf: _WordBuf) -> None:
        nxt = self._peek(1)
        if nxt == "":
            raise ShellSyntaxError("trailing backslash")
        self.pos += 2
        if nxt == "\n":
            return  # line continuation
        buf.add(nxt, quoted=True)

    def _single_quoted(self) -> str:
        end = self.src.find("'", self.pos + 1)
        if end < 0:
            raise ShellSyntaxError("unterminated single quote")
        text = self.src[self.pos + 1 : end]
        self.pos = end + 1
        return text

    def _double_quoted(self, buf: _WordBuf, *, closing: bool) -> str:
        """Read a double-quoted body (or an expanding heredoc body when not `closing`)."""
        out: list[str] = []
        src = self.src
        while self.pos < len(src):
            ch = src[self.pos]
            if closing and ch == '"':
                self.pos += 1
                return "".join(out)
            if ch == "\\":
                nxt = self._peek(1)
                if nxt == "":
                    raise ShellSyntaxError("trailing backslash")
                self.pos += 2
                if nxt == "\n":
                    continue
                out.append(nxt if nxt in '$`"\\' else "\\" + nxt)
            elif ch == "$":
                sub = _WordBuf()
                self._dollar(sub)
                buf.dynamic = buf.dynamic or sub.dynamic
                out.append("".join(sub.parts))
            elif ch == "`":
                sub = _WordBuf()
                self._backtick(sub)
                buf.dynamic = True
                out.append("".join(sub.parts))
            else:
                out.append(ch)
                self.pos += 1
        if closing:
            raise ShellSyntaxError("unterminated double quote")
        return "".join(out)

    # --- expansions -----------------------------------------------------------------

    def _dollar(self, buf: _WordBuf) -> None:
        nxt = self._peek(1)
        start = self.pos
        if nxt == "(":
            self.pos += 2
            self._substitution(buf)
            return
        if nxt == "{":
            self.pos += 2
            self._braced(buf)
            buf.add(self.src[start : self.pos])
            return
        if nxt == "'":
            # ANSI-C quoting: escapes like \x72 can spell any command name.
            self.pos += 1
            buf.add(self._ansi_c(), quoted=True)
            buf.dynamic = True
            return
        if nxt == '"':
            self.pos += 2
            buf.add(self._double_quoted(buf, closing=True), quoted=True)
            buf.dynamic = True
            return
        if nxt.isalnum() or nxt in "_@*#?$!-":
            self.pos += 2
            if nxt.isalpha() or nxt == "_":
                while self.pos < len(self.src) and (
                    self.src[self.pos].isalnum() or self.src[self.pos] == "_"
                ):
                    self.pos += 1
            buf.add(self.src[start : self.pos])
            buf.dynamic = True
            return
        buf.add("$")
        self.pos += 1

    def _ansi_c(self) -> str:
        i = self.pos + 1
        while i < len(self.src):
            if self.src[i] == "\\":
                i += 2
                continue
            if self.src[i] == "'":
                text = self.src[self.pos + 1 : i]
                self.pos = i + 1
                return text
            i += 1
        raise ShellSyntaxError("unterminated $'...' quote")

    def _braced(self, buf: _WordBuf) -> None:
        """`${…}` (after `${`): may hold `$(…)`, backticks and quotes; all lexed."""
        depth = 1
        while self.pos < len(self.src):
            ch = self.src[self.pos]
            if ch == "\\":
                self.pos += 2
            elif ch == "'":
                self._single_quoted()
            elif ch == '"':
                self.pos += 1
                self._double_quoted(_WordBuf(), closing=True)
            elif ch == "$":
                self._dollar(_WordBuf())
            elif ch == "`":
                self._backtick(_WordBuf())
            elif ch == "{":
                depth += 1
                self.pos += 1
            elif ch == "}":
                depth -= 1
                self.pos += 1
                if depth == 0:
                    buf.dynamic = True
                    return
            else:
                self.pos += 1
        raise ShellSyntaxError("unterminated ${...}")

    def _substitution(self, buf: _WordBuf) -> None:
        """`$(…)` / `<(…)` / `>(…)` body (after the opening paren): lexed recursively."""
        start = self.pos
        inner = _Lexer(self.src, self.pos, self.depth + 1, paren=True)
        end = inner.run()
        self.nested.append(inner.tokens)
        self.nested.extend(inner.nested)
        self.pos = end
        buf.add(self.src[start - 2 : end])
        buf.dynamic = True

    def _backtick(self, buf: _WordBuf) -> None:
        i = self.pos + 1
        body: list[str] = []
        while i < len(self.src):
            ch = self.src[i]
            if ch == "\\" and i + 1 < len(self.src) and self.src[i + 1] in "`\\$":
                body.append(self.src[i + 1])
                i += 2
                continue
            if ch == "`":
                inner = _Lexer("".join(body), 0, self.depth + 1, paren=False)
                inner.run()
                self.nested.append(inner.tokens)
                self.nested.extend(inner.nested)
                buf.add(self.src[self.pos : i + 1])
                buf.dynamic = True
                self.pos = i + 1
                return
            body.append(ch)
            i += 1
        raise ShellSyntaxError("unterminated backtick")

    # --- operators and heredocs -------------------------------------------------------

    def _operator(self, buf: _WordBuf) -> bool:
        """Emit one operator; True if it closes this lexer's `$(`."""
        word = buf.take()
        # `2>`: an adjacent fd number belongs to the redirection, not the words.
        if word is not None and not (
            word.literal and word.text.isdigit() and self.src[self.pos] in "<>"
        ):
            self._emit_word(word)
        op = next(o for o in _OPERATORS if self.src.startswith(o, self.pos))
        self.pos += len(op)
        if op == "(":
            self._open_parens += 1
        elif op == ")":
            if self.paren and self._open_parens == 0:
                if self._pending:
                    raise ShellSyntaxError("unterminated heredoc")
                return True
            self._open_parens -= 1
        self.tokens.append(Op(op))
        return False

    def _closes_paren(self, check: str, delimiter: str) -> bool:
        rest = check[len(delimiter) :].lstrip(" \t")
        return self.paren and check.startswith(delimiter) and rest.startswith(")")

    def _read_heredoc_bodies(self) -> None:
        while self._pending:
            doc = self._pending.pop(0)
            body_start = self.pos
            while True:
                if self.pos >= len(self.src):
                    raise ShellSyntaxError("unterminated heredoc")
                nl = self.src.find("\n", self.pos)
                line_end = len(self.src) if nl < 0 else nl
                line = self.src[self.pos : line_end]
                check = line.lstrip("\t") if doc.strip_tabs else line
                if check == doc.delimiter:
                    body = self.src[body_start : self.pos]
                    self.pos = line_end + (0 if nl < 0 else 1)
                    break
                if self._closes_paren(check, doc.delimiter):
                    # `EOF)` closing a `$(…)` on the delimiter line (bash accepts it).
                    body = self.src[body_start : self.pos]
                    self.pos += len(line) - len(check) + len(doc.delimiter)
                    break
                self.pos = line_end + 1
            if doc.expands:
                # An unquoted delimiter: `$(…)` and backticks in the body run.
                sub = _Lexer(body, 0, self.depth + 1, paren=False)
                sub._double_quoted(_WordBuf(), closing=False)
                self.nested.extend(sub.nested)


def lex(src: str) -> tuple[list[Token], list[list[Token]]]:
    """Tokenize `src`; return its tokens and every nested substitution's tokens.

    Raises:
        ShellSyntaxError: unreadable or over `MAX_SCRIPT_CHARS`.
    """
    if not isinstance(src, str) or len(src) > MAX_SCRIPT_CHARS:
        raise ShellSyntaxError("command missing or too long")
    if "\x00" in src:
        raise ShellSyntaxError("NUL in command")
    lexer = _Lexer(src, 0, 0, paren=False)
    lexer.run()
    return lexer.tokens, lexer.nested


def split_commands(tokens: list[Token]) -> list[SimpleCommand]:
    """Group tokens into simple commands at separators, pipes and parens.

    Raises:
        ShellSyntaxError: a redirection without a target word, or an unknown operator.
    """
    commands: list[SimpleCommand] = []
    words: list[Word] = []
    redirects: list[tuple[str, Word]] = []
    fed = False
    i = 0

    def flush(next_fed: bool) -> None:
        nonlocal words, redirects, fed
        if words or redirects:
            commands.append(SimpleCommand(tuple(words), tuple(redirects), fed))
        words, redirects, fed = [], [], next_fed

    while i < len(tokens):
        tok = tokens[i]
        if isinstance(tok, Word):
            words.append(tok)
        elif tok.text in SEPARATORS:
            flush(False)
        elif tok.text in PIPES:
            flush(True)
        elif tok.text in REDIRECTS or tok.text in HEREDOCS:
            target = tokens[i + 1] if i + 1 < len(tokens) else None
            if not isinstance(target, Word):
                raise ShellSyntaxError("redirection without a target")
            redirects.append((tok.text, target))
            if tok.text in HEREDOCS or tok.text in {"<<<", "<"}:
                fed = True
            i += 1
        else:
            raise ShellSyntaxError("unknown operator")
        i += 1
    flush(False)
    return commands


def parse_script(src: str) -> list[SimpleCommand]:
    """Every simple command in `src`, including those inside substitutions.

    Raises:
        ShellSyntaxError: see `lex` and `split_commands`.
    """
    tokens, nested = lex(src)
    commands = split_commands(tokens)
    for inner in nested:
        commands.extend(split_commands(inner))
    return commands


__all__ = [
    "MAX_SCRIPT_CHARS",
    "OUTPUT_REDIRECTS",
    "Op",
    "ShellSyntaxError",
    "SimpleCommand",
    "Token",
    "Word",
    "lex",
    "parse_script",
    "split_commands",
]
