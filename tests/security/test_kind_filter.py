"""Security tests: the multi-kind listing filter fails closed (docs/security.md C24).

`GET /api/items?kind=a,b` is untrusted input: every name is syntax-checked,
at most `MAX_QUERY_KINDS` are accepted, empty elements and repeated `kind`
keys are a 400, and the SQLite adapter binds every kind into a fixed-width
`IN` list of a static SQL constant (never text built from the request).
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest

from preview_dashboard.adapters.sqlite import repository as sqlite_repository
from preview_dashboard.adapters.sqlite.connection import connect, default_db_path
from preview_dashboard.adapters.sqlite.repository import SqliteItemRepository
from preview_dashboard.domain.errors import ValidationError
from preview_dashboard.domain.query import MAX_QUERY_KINDS, ItemQuery
from tests.builders import make_item, ulid
from tests.viewer_support import ViewerEnv, make_env, owner_headers

pytestmark = pytest.mark.security

_MULTI_KIND_SQL = (
    "_LIST_KINDS_SQL",
    "_LIST_KINDS_CURSOR_SQL",
    "_LIST_FOLDER_KINDS_SQL",
    "_LIST_FOLDER_KINDS_CURSOR_SQL",
)


@pytest.fixture(scope="module")
def env() -> ViewerEnv:
    env = make_env()
    env.publish({"index.html": b"<p>x</p>"}, title="Page")
    env.publish({"notes.txt": b"hello"}, title="Notes")
    return env


@pytest.mark.parametrize(
    "query",
    [
        "kind=html,",  # trailing comma: empty element
        "kind=,html",
        "kind=html,,text",
        "kind=,",
        "kind=html,BAD",
        "kind=html,te%20xt",
        "kind=html,x'%20OR%201=1--",
        "kind=" + ",".join(f"k{n}" for n in range(MAX_QUERY_KINDS + 1)),
        "kind=" + ",".join(["html"] * (MAX_QUERY_KINDS + 1)),  # counted before dedupe
        "kind=html&kind=text",  # repeated key: one meaning per URL
        "kind=html;text",
    ],
)
def test_bad_kind_filters_are_400(env: ViewerEnv, query: str) -> None:
    response = env.dash_client().get(f"/api/items?{query}", headers=owner_headers())
    assert response.status_code == 400
    assert set(response.json()) == {"error", "request_id"}


def test_max_kinds_is_accepted(env: ViewerEnv) -> None:
    names = ",".join(["html", "text", *(f"k{n}" for n in range(MAX_QUERY_KINDS - 2))])
    response = env.dash_client().get(f"/api/items?kind={names}", headers=owner_headers())
    assert response.status_code == 200
    assert {i["title"] for i in response.json()["items"]} == {"Page", "Notes"}


def test_empty_kind_filter_returns_all_kinds(env: ViewerEnv) -> None:
    response = env.dash_client().get("/api/items?kind=", headers=owner_headers())
    assert response.status_code == 200
    assert {i["title"] for i in response.json()["items"]} == {"Page", "Notes"}


@pytest.mark.parametrize("name", _MULTI_KIND_SQL)
def test_multi_kind_sql_is_a_fixed_width_in_list(name: str) -> None:
    sql = getattr(sqlite_repository, name)
    assert isinstance(sql, str)
    (in_list,) = re.findall(r"kind IN \(([?, ]*)\)", sql)
    assert in_list.count("?") == MAX_QUERY_KINDS


def test_padding_refuses_out_of_range_counts() -> None:
    pad = sqlite_repository._padded_kinds
    assert pad(("a", "b")) == ("a", "b", *("b",) * (MAX_QUERY_KINDS - 2))
    with pytest.raises(ValidationError):
        pad(())
    with pytest.raises(ValidationError):
        pad(tuple(f"k{n}" for n in range(MAX_QUERY_KINDS + 1)))


def test_kind_values_are_bound_not_spliced(tmp_path: Path) -> None:
    factory = functools.partial(connect, default_db_path(tmp_path))
    factory().close()
    repo = SqliteItemRepository(factory)
    repo.add(make_item(1, kind="html"))
    repo.add(make_item(2, kind="text"))
    # Syntax-valid names that would change the query if spliced into SQL text
    # (`-` starts a comment when doubled) match nothing and break nothing.
    got = repo.list(ItemQuery(kinds=("html", "x--", "or-1"))).items
    assert [i.id for i in got] == [ulid(1)]
