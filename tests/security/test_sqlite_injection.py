"""Security tests for control C24: SQLite adapter, parameterized SQL only.

Covers SQL-metacharacter round-tripping through every free-text field,
cursor tampering (must never reach the repository layer at all -- decoding
happens in `domain.query` before any SQL runs), and a static AST
*allowlist*: the SQL argument of every `execute()`/`executemany()`/
`executescript()` call in `adapters/sqlite` must be a string literal, a
module-level string constant bound exactly once, or a local bound once from
a same-module helper whose every return yields such a constant. Negative
self-tests prove the checker catches the known evasions.
"""

from __future__ import annotations

import ast
import functools
from collections import Counter
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite.connection import connect, default_db_path
from preview_dashboard.adapters.sqlite.repository import SqliteItemRepository
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.query import ItemQuery
from tests.builders import make_file, make_item

pytestmark = pytest.mark.security

_TEXT_FIELD_PAYLOADS = [
    "Robert'); DROP TABLE items;--",
    "'; DROP TABLE items; --",
    "x' OR '1'='1",
    "%_\\\"'; -- /* */ OR 1=1",
    "\x00null-byte",
    "a" + chr(0x2028) + "line separator",  # U+2028 LINE SEPARATOR (Zl char sanitize_* strips)
    "'||(SELECT sql FROM sqlite_master)||'",
]

# `validate_relpath` forbids most SQL metacharacters outright as path
# separators/URL delimiters (docs/security.md C7): backslash, colon,
# percent, question mark, hash, semicolon, double quote, angle brackets,
# pipe, star, and all control characters. The single quote is the one
# deliberately still allowed there ("it's.txt" in the port docstring), so
# it is the metacharacter that actually reaches the SQL layer for a
# relpath; `test_paths.py` covers the full forbidden-character list.
_RELPATH_PAYLOADS = [
    "it's.txt",
    "a' OR '1'='1.txt",
    "100_pct'--/x.txt",
    "a' UNION SELECT sql FROM sqlite_master --.txt",
]


class TestMetacharacterRoundTrip:
    """Every free-text field must round-trip unchanged, never be interpreted as SQL."""

    @pytest.mark.parametrize("payload", _TEXT_FIELD_PAYLOADS)
    def test_title_round_trips(self, tmp_path: Path, payload: str) -> None:
        repo = SqliteItemRepository(functools.partial(connect, default_db_path(tmp_path)))
        # sanitize_title requires at least one visible char; prefix a stable
        # visible one so every payload is still a valid title however
        # sanitizing (control/bidi stripping) treats the rest of it.
        item = make_item(1, title="T " + payload)
        repo.add(item)
        assert repo.get(item.id).title == item.title
        assert {i.id for i in repo.list(ItemQuery()).items} == {item.id}

    @pytest.mark.parametrize("payload", _TEXT_FIELD_PAYLOADS)
    def test_description_round_trips(self, tmp_path: Path, payload: str) -> None:
        repo = SqliteItemRepository(functools.partial(connect, default_db_path(tmp_path)))
        item = make_item(1, description=payload)
        repo.add(item)
        assert repo.get(item.id).description == item.description

    @pytest.mark.parametrize("relpath", _RELPATH_PAYLOADS)
    def test_relpath_round_trips(self, tmp_path: Path, relpath: str) -> None:
        repo = SqliteItemRepository(functools.partial(connect, default_db_path(tmp_path)))
        item = make_item(
            1,
            files=(make_file(relpath, blob=1, media_type="text/plain"),),
            entry_file=relpath,
        )
        repo.add(item)
        assert repo.get(item.id).files[0].relpath == relpath

    def test_metacharacters_do_not_alter_other_rows(self, tmp_path: Path) -> None:
        repo = SqliteItemRepository(functools.partial(connect, default_db_path(tmp_path)))
        repo.add(make_item(1, title="Robert'); DROP TABLE items;--"))
        repo.add(make_item(2))
        assert repo.get(make_item(2).id).title == "Item 2"
        assert len(repo.list(ItemQuery()).items) == 2


_MALICIOUS_CURSORS = [
    "v1:1:0:1' OR '1'='1",
    "'; DROP TABLE items;--",
    "v1:1:0:" + "A" * 25 + "'",  # near-valid ULID with a trailing quote
    "v1:1:0:" + "'" * 26,
    "",
    "not-base64!!!",
]


class TestCursorTamperingNeverReachesSql:
    """A malicious cursor must be rejected by `domain.query` decoding, before
    any SQL is built from it -- the repository never sees an undecoded string.
    """

    @pytest.mark.parametrize("cursor", _MALICIOUS_CURSORS)
    def test_query_construction_rejects_tampered_cursor(self, cursor: str) -> None:
        with pytest.raises(ValidationError):
            ItemQuery(cursor=cursor)

    @pytest.mark.parametrize("cursor", _MALICIOUS_CURSORS)
    def test_repository_list_is_never_reached_with_a_tampered_cursor(
        self, tmp_path: Path, cursor: str
    ) -> None:
        repo = SqliteItemRepository(functools.partial(connect, default_db_path(tmp_path)))
        repo.add(make_item(1))
        # ItemQuery(...) raises before repo.list() could ever be called with
        # the tampered cursor; that construction-time rejection is the
        # actual control under test here.
        with pytest.raises(ValidationError):
            query = ItemQuery(cursor=cursor)
            repo.list(query)


# --- static AST allowlist: SQL text is always a static constant ---------------

_ADAPTER_DIR = (
    Path(__file__).resolve().parents[2] / "src" / "preview_dashboard" / "adapters" / "sqlite"
)
_EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript"})
_FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _binding_counts(root: ast.AST) -> Counter[str]:
    """Count every way a name can be (re)bound anywhere under `root` (conservative)."""
    counts: Counter[str] = Counter()
    for node in ast.walk(root):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            counts[node.id] += 1
        elif isinstance(node, ast.arg):
            counts[node.arg] += 1
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            counts[node.name] += 1
        elif isinstance(node, ast.alias):
            counts[(node.asname or node.name).split(".")[0]] += 1
        elif isinstance(node, ast.Global | ast.Nonlocal):
            counts.update(node.names)
        elif isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
            counts[node.name] += 1
    return counts


def _is_str_constant(node: ast.expr | None) -> bool:
    # Implicit literal concatenation ("a" "b") is already one Constant in the AST.
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _module_constants(tree: ast.Module) -> frozenset[str]:
    """Names assigned a str literal at module top level and bound nowhere else."""
    counts = _binding_counts(tree)
    names: set[str] = set()
    for stmt in tree.body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and _is_str_constant(stmt.value)
        ):
            names.add(stmt.targets[0].id)
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and _is_str_constant(stmt.value)
        ):
            names.add(stmt.target.id)
    return frozenset(n for n in names if counts[n] == 1)


def _own_nodes(func: _FunctionNode) -> list[ast.AST]:
    """Nodes of `func`'s body, not descending into nested functions/lambdas/classes."""
    found: list[ast.AST] = []
    stack: list[ast.AST] = list(func.body)
    while stack:
        node = stack.pop()
        found.append(node)
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, _SCOPE_NODES):
                stack.append(child)
    return found


class _SqlAllowlistChecker:
    """Finds execute-family calls whose SQL argument isn't provably static."""

    def __init__(self, source: str, filename: str = "<src>") -> None:
        self._tree = ast.parse(source, filename=filename)
        self._constants = _module_constants(self._tree)
        self._functions: dict[str, list[_FunctionNode]] = {}
        for node in ast.walk(self._tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self._functions.setdefault(node.name, []).append(node)
        self._class_names = {n.name for n in ast.walk(self._tree) if isinstance(n, ast.ClassDef)}
        self.checked_calls = 0

    def offenses(self) -> list[str]:
        """Return `line: reason` for every call that fails the allowlist."""
        found: list[str] = []
        self._visit(self._tree, None, found)
        return found

    def _visit(self, node: ast.AST, func: _FunctionNode | None, found: list[str]) -> None:
        for child in ast.iter_child_nodes(node):
            inner = child if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else func
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in _EXECUTE_METHODS
            ):
                self.checked_calls += 1
                reason = self._check_call(child, func)
                if reason is not None:
                    found.append(f"{child.lineno}: {reason}")
            self._visit(child, inner, found)

    def _check_call(self, call: ast.Call, func: _FunctionNode | None) -> str | None:
        if call.args:
            sql: ast.expr = call.args[0]
            if isinstance(sql, ast.Starred):
                return "starred SQL argument"
        else:
            by_kw = [kw.value for kw in call.keywords if kw.arg == "sql"]
            if not by_kw:
                return "no statically visible SQL argument"
            sql = by_kw[0]
        if _is_str_constant(sql):
            return None
        if isinstance(sql, ast.Name):
            if sql.id in self._constants:
                return None
            if func is not None and self._is_helper_bound_local(sql.id, func):
                return None
            return f"name {sql.id!r} is not a once-bound module-level str constant"
        return f"SQL argument is a {type(sql).__name__}, not a constant"

    def _is_helper_bound_local(self, name: str, func: _FunctionNode) -> bool:
        """`name` bound once in `func` from a same-module helper returning constants."""
        if _binding_counts(func)[name] != 1:
            return False
        for node in _own_nodes(func):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            index: int | None
            if isinstance(target, ast.Name) and target.id == name:
                index = None
            elif isinstance(target, ast.Tuple) and not any(
                isinstance(e, ast.Starred) for e in target.elts
            ):
                positions = [
                    i for i, e in enumerate(target.elts) if isinstance(e, ast.Name) and e.id == name
                ]
                if len(positions) != 1:
                    continue
                index = positions[0]
            else:
                continue
            return self._helper_returns_constants(node.value, index)
        return False

    def _helper_returns_constants(self, value: ast.expr, index: int | None) -> bool:
        if not isinstance(value, ast.Call):
            return False
        callee = value.func
        if isinstance(callee, ast.Name):
            helper_name = callee.id
        elif isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            if callee.value.id not in {"self", "cls", *self._class_names}:
                return False
            helper_name = callee.attr
        else:
            return False
        helpers = self._functions.get(helper_name, [])
        return bool(helpers) and all(self._returns_constants(h, index) for h in helpers)

    def _returns_constants(self, helper: _FunctionNode, index: int | None) -> bool:
        returns = [n for n in _own_nodes(helper) if isinstance(n, ast.Return)]
        if not returns:
            return False
        for ret in returns:
            value = ret.value
            if index is not None:
                if not isinstance(value, ast.Tuple) or len(value.elts) <= index:
                    return False
                if any(isinstance(e, ast.Starred) for e in value.elts[: index + 1]):
                    return False
                value = value.elts[index]
            if not (isinstance(value, ast.Name) and value.id in self._constants):
                return False
        return True


def _offenses(source: str) -> list[str]:
    return _SqlAllowlistChecker(source).offenses()


class TestSqlAllowlistOnAdapter:
    def test_every_execute_call_passes_the_allowlist(self) -> None:
        offenders: list[str] = []
        checked = 0
        for path in sorted(_ADAPTER_DIR.glob("*.py")):
            checker = _SqlAllowlistChecker(path.read_text(encoding="utf-8"), str(path))
            offenders.extend(f"{path.name}:{o}" for o in checker.offenses())
            checked += checker.checked_calls
        assert offenders == []
        # Guards against the check silently passing over nothing (path typo,
        # or a refactor that hides the calls from the walker).
        assert checked >= 20

    def test_adapter_directory_is_not_empty(self) -> None:
        assert list(_ADAPTER_DIR.glob("*.py"))


class TestSqlAllowlistCatchesEvasions:
    """Negative self-tests: each known way to smuggle dynamic SQL is flagged."""

    def test_variable_built_from_fstring(self) -> None:
        src = "def f(conn, x):\n    sql = f'SELECT * FROM t WHERE a = {x}'\n    conn.execute(sql)\n"
        assert _offenses(src)

    def test_sql_kwarg_with_concatenation(self) -> None:
        src = "def f(conn, x):\n    conn.execute(sql='SELECT * FROM t WHERE a = ' + x)\n"
        assert _offenses(src)

    def test_str_join(self) -> None:
        src = "def f(conn, x):\n    conn.execute(' '.join(['SELECT', x, 'FROM t']))\n"
        assert _offenses(src)

    def test_helper_function_call(self) -> None:
        src = (
            "def build(x):\n    return 'SELECT ' + x\ndef f(conn, x):\n    conn.execute(build(x))\n"
        )
        assert _offenses(src)

    def test_helper_bound_local_returning_dynamic_sql(self) -> None:
        src = (
            "_A = 'SELECT 1'\n"
            "def q(x):\n    if x:\n        return _A, ()\n    return f'SELECT {x}', ()\n"
            "def f(conn, x):\n    sql, p = q(x)\n    conn.execute(sql, p)\n"
        )
        assert _offenses(src)

    def test_module_constant_rebound(self) -> None:
        src = "_A = 'SELECT 1'\n_A += ' OR 1=1'\ndef f(conn):\n    conn.execute(_A)\n"
        assert _offenses(src)

    def test_module_constant_rebound_via_global(self) -> None:
        src = (
            "_A = 'SELECT 1'\n"
            "def g(x):\n    global _A\n    _A = x\n"
            "def f(conn):\n    conn.execute(_A)\n"
        )
        assert _offenses(src)

    def test_module_level_concatenated_constant(self) -> None:
        src = "import os\n_A = 'SELECT ' + os.environ['X']\ndef f(conn):\n    conn.execute(_A)\n"
        assert _offenses(src)

    def test_percent_format_and_dot_format(self) -> None:
        assert _offenses("def f(c, x):\n    c.execute('SELECT %s' % x)\n")
        assert _offenses("def f(c, x):\n    c.executemany('SELECT {}'.format(x), [])\n")

    def test_starred_or_hidden_sql_argument(self) -> None:
        assert _offenses("def f(c, a):\n    c.execute(*a)\n")
        assert _offenses("def f(c, kw):\n    c.execute(**kw)\n")


class TestSqlAllowlistAcceptsStaticSql:
    def test_literal_and_implicit_concatenation(self) -> None:
        assert _offenses("def f(c):\n    c.execute('SELECT 1 ' 'FROM t')\n") == []

    def test_once_bound_module_constant_positional_and_kwarg(self) -> None:
        src = (
            "_A = ('SELECT 1 '\n      'FROM t')\n"
            "def f(c):\n    c.execute(_A)\n    c.execute(sql=_A)\n"
        )
        assert _offenses(src) == []

    def test_helper_returning_only_constants(self) -> None:
        src = (
            "_A = 'SELECT 1'\n_B = 'SELECT 2'\n"
            "class R:\n"
            "    @staticmethod\n"
            "    def q(x):\n        if x:\n            return _A, (x,)\n        return _B, ()\n"
            "    def f(self, c, x):\n        sql, p = self.q(x)\n        c.execute(sql, p)\n"
        )
        assert _offenses(src) == []
