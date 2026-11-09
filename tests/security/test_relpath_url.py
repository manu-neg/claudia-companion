"""Security tests for preview URL relpath decoding (docs/security.md C7, C20, I2).

The raw URL tail is percent-decoded exactly once and re-validated; every
traversal/encoding trick in the matrix must be rejected, and the encoder
must round-trip every valid relpath.
"""

from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.responses import PlainTextResponse
from hypothesis import given
from hypothesis import strategies as st

from preview_dashboard.domain.errors import InvalidPathError
from preview_dashboard.domain.paths import validate_relpath
from preview_dashboard.interfaces.viewer.relpath_url import (
    decode_relpath_tail,
    encode_relpath_url,
    raw_path_tail,
    relpath_from_scope,
)
from tests.viewer_support import OWNER, PREVIEW_HOST, call_asgi, preview_app

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("index.html", "index.html"),
        ("sub/x.html", "sub/x.html"),
        ("a%20b.png", "a b.png"),
        ("r%C3%A9sum%C3%A9.pdf", "résumé.pdf"),
        ("it's.txt", "it's.txt"),
        ("it%27s.txt", "it's.txt"),
        ("(1)!.txt", "(1)!.txt"),
        ("%28a%29.txt", "(a).txt"),
        ("%E6%97%A5%E6%9C%AC/%E8%AA%9E.md", "日本/語.md"),
    ],
)
def test_valid_tails_decode_once(raw: str, expected: str) -> None:
    assert decode_relpath_tail(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        # Traversal, literal and encoded.
        "..",
        "../etc/passwd",
        "a/../../etc/passwd",
        "%2e%2e/etc/passwd",
        "%2E%2E/%2E%2E/root/.ssh/id_rsa",
        ".%2e/x",
        "%2e/x",
        "a/%2e%2e",
        # Double encoding: a second decode would yield traversal.
        "%252e%252e/etc/passwd",
        "%252E%252E%252Fetc",
        "%25",
        "a%25b",
        # Encoded separators.
        "a%2fb",
        "a%2Fb",
        "..%2f..%2fetc%2fpasswd",
        "a%5cb",
        "..%5C..%5Cwindows",
        # Raw backslash and absolute paths.
        "a\\b",
        "..\\..\\x",
        "/etc/passwd",
        "%2fetc%2fpasswd",
        "//etc/passwd",
        # Fullwidth / compatibility look-alikes (raw and encoded).
        "\uff0e\uff0e/x",
        "%EF%BC%8E%EF%BC%8E/x",  # fullwidth dots
        "%EF%BC%8F",  # fullwidth solidus
        "a%EF%BC%BCb",  # fullwidth reverse solidus
        "%E2%88%95etc",  # division slash
        # Control characters, NUL, bidi.
        "a%00b",
        "a%0d%0ab",
        "a%09b",
        "%E2%80%AEtxt.exe",
        # Malformed escapes / invalid UTF-8.
        "a%",
        "a%2",
        "a%zz",
        "a%C3",
        "a%C3%28",
        "a%FF",
        "%C0%AE%C0%AE/x",  # overlong '.'
        # Encoded unreserved characters are non-canonical.
        "%61.txt",
        "a%2Etxt",
        "a%7E",
        # Other structure.
        "",
        "a//b",
        "a/",
        "~/x",
        "a b",  # raw space never comes from an encoder
        "a?b",
        "a#b",
        'a"b',
        "a<b>",
        "é.txt",  # raw non-ASCII
        "CON",
        "nul.txt",
    ],
)
def test_attack_matrix_is_rejected(raw: str) -> None:
    with pytest.raises(InvalidPathError):
        decode_relpath_tail(raw)


@pytest.mark.parametrize(
    ("raw_path", "segments", "tail"),
    [
        (b"/p/01ARZ3NDEKTSV4RRFFQ69G5FAV/sub/x.html", 2, "sub/x.html"),
        (b"/p/ID/a%2Fb", 2, "a%2Fb"),
        (b"/p/ID/%252e%252e", 2, "%252e%252e"),
    ],
)
def test_raw_path_tail_keeps_encoding(raw_path: bytes, segments: int, tail: str) -> None:
    assert raw_path_tail({"raw_path": raw_path}, segments) == tail


@pytest.mark.parametrize(
    "scope",
    [
        {},
        {"raw_path": "/p/ID/x"},  # str, not bytes
        {"raw_path": b"p/ID/x"},
        {"raw_path": b"/p/ID"},
        {"raw_path": b"/p/ID/\xc3\xa9"},
    ],
)
def test_raw_path_tail_fails_closed(scope: dict[str, object]) -> None:
    with pytest.raises(InvalidPathError):
        raw_path_tail(scope, 2)


async def test_route_uses_raw_path_not_decoded_path() -> None:
    """Starlette's decoded path turns `%2F` into `/`; the raw path keeps it."""
    app = preview_app()
    seen: list[str] = []

    @app.inner.get("/p/{item_id}/{rest:path}")
    def serve(request: Request, item_id: str, rest: str) -> PlainTextResponse:
        try:
            seen.append(relpath_from_scope(request.scope, 2))
        except InvalidPathError:
            return PlainTextResponse("bad", status_code=400)
        return PlainTextResponse("ok")

    headers = [(b"host", PREVIEW_HOST.encode()), (b"tailscale-user-login", OWNER.encode())]
    for raw, status in [
        (b"/p/ID/sub/x.html", 200),
        (b"/p/ID/..%2F..%2Fetc%2Fpasswd", 400),
        (b"/p/ID/%252e%252e/x", 400),
        (b"/p/ID/%2e%2e/x", 400),
    ]:
        # Mimic uvicorn: `path` is the once-decoded raw path.
        from urllib.parse import unquote

        result = await call_asgi(app, path=unquote(raw.decode()), raw_path=raw, headers=headers)
        assert result.status == status, raw
    assert seen == ["sub/x.html"]


@pytest.mark.parametrize("which", ["preview", "dashboard"])
@pytest.mark.parametrize(
    "raw",
    [
        b"/p/AAA%2Fextra/foo.js",
        b"/p/AAA%2fextra/foo.js",
        b"/p/ID/a%5Cb.js",
        b"/p/ID/a%5cb.js",
        b"/p/ID/%252e%252e/x",
        b"/static/%2e%2e%2Fconfig.py",
        b"/api/items/AAA%2F..",
    ],
)
async def test_raw_path_guard_rejects_encoded_separators_centrally(which: str, raw: bytes) -> None:
    """Review fix 3: `%2F`/`%5C`/`%25` anywhere → 400 before any route runs,
    so decoded path params (the item id) can never disagree with the raw path."""
    from urllib.parse import unquote

    from tests.viewer_support import DASH_HOST, dashboard_app

    app = preview_app() if which == "preview" else dashboard_app()
    reached: list[str] = []

    @app.inner.get("/p/{item_id}/{rest:path}")
    def serve(item_id: str, rest: str) -> PlainTextResponse:
        reached.append(item_id)
        return PlainTextResponse("ok")

    host = PREVIEW_HOST if which == "preview" else DASH_HOST
    headers = [(b"host", host.encode()), (b"tailscale-user-login", OWNER.encode())]
    result = await call_asgi(app, path=unquote(raw.decode()), raw_path=raw, headers=headers)
    assert result.status == 400
    assert reached == []
    assert result.header("content-security-policy")  # still gets the security headers


def test_encode_is_per_segment() -> None:
    assert encode_relpath_url("sub/a b/résumé.pdf") == "sub/a%20b/r%C3%A9sum%C3%A9.pdf"
    assert encode_relpath_url("it's (1)!.txt") == "it%27s%20%281%29%21.txt"


@pytest.mark.parametrize("bad", ["../x", "a\\b", "/abs", "a%b", ""])
def test_encode_rejects_invalid_relpaths(bad: str) -> None:
    with pytest.raises(InvalidPathError):
        encode_relpath_url(bad)


def _valid(text: str) -> bool:
    try:
        validate_relpath(text)
    except InvalidPathError:
        return False
    return True


_segment = st.text(
    alphabet=st.characters(blacklist_categories=["Cs"], max_codepoint=0x2FFFF),
    min_size=1,
    max_size=12,
)


@given(st.lists(_segment, min_size=1, max_size=4).map("/".join).filter(_valid))
def test_round_trip(relpath: str) -> None:
    encoded = encode_relpath_url(relpath)
    assert encoded.isascii()
    assert decode_relpath_tail(encoded) == relpath


@given(st.lists(_segment, min_size=1, max_size=4).map("/".join).filter(_valid))
def test_double_encoded_never_decodes_to_the_path(relpath: str) -> None:
    once = encode_relpath_url(relpath)
    twice = "/".join(s.replace("%", "%25") for s in once.split("/"))
    if twice == once:
        return  # nothing was encoded in the first place
    with pytest.raises(InvalidPathError):
        decode_relpath_tail(twice)
