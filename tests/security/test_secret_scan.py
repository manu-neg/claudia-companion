"""Security tests for the admin content secret scan (docs/security.md C15, ADR 0008).

Covers: every rule fires, detection is independent of chunking (including
secrets split across chunk and scan-window boundaries), no false positives
on look-alikes, the error never contains the secret, scanning stays linear
on pathological input (ReDoS), and the publish/update paths reject secrets
in content *and* metadata without leaving blobs behind.

Samples are assembled at runtime from fragments so this file never contains
a literal token that repository secret scanners (gitleaks) would flag.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from preview_dashboard.adapters.secret_scan import (
    DEFAULT_RULES,
    MAX_MATCH_BYTES,
    RegexSecretScanner,
)
from preview_dashboard.application import IncomingFile, LifecycleService
from preview_dashboard.domain.errors import SecretDetectedError
from tests.app_support import command, incoming, make_publish
from tests.builders import make_item
from tests.fakes import FakeContentScanner, FixedClock, InMemoryItemRepository

pytestmark = pytest.mark.security


def _j(*parts: str) -> bytes:
    return "".join(parts).encode()


_DASHES = "-" * 5
SAMPLES: dict[str, list[bytes]] = {
    "SSH2 private key": [_j("-" * 4, " BEGIN SSH2 ", "ENCRYPTED PRIVATE KEY", " ", "-" * 4)],
    "PEM private key": [
        _j(_DASHES, "BEGIN ", "RSA PRIVATE KEY", _DASHES),
        _j("BEGIN ", "RSA PRIVATE KEY"),  # dashes stripped or mangled
        _j("~~~~BEGIN ", "PRIVATE KEY~~~~"),
        _j(_DASHES, "BEGIN SSH2 ", "ENCRYPTED PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "A1 B2 C3 D4 E5 F6 G7 ", "PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "EC PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "DSA PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "OPENSSH PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "ENCRYPTED PRIVATE KEY", _DASHES),
        _j(_DASHES, "BEGIN ", "PGP PRIVATE KEY BLOCK", _DASHES),
    ],
    "PuTTY private key": [_j("PuTTY-User-", "Key-File-3: ssh-ed25519")],
    "AWS access key id": [_j("AK", "IA", "Q" * 16), _j("AS", "IA", "ABCDEFGHIJKLMN23")],
    "GitHub token": [_j("gh", "p_", "a" * 36), _j("gh", "s_", "B1" * 18)],
    "GitHub fine-grained token": [_j("github", "_pat_", "11AAAAAAA0", "x_" * 6)],
    "Anthropic API key": [_j("sk-", "ant-", "api03-", "A" * 20)],
    "OpenAI API key": [_j("sk-", "proj-", "A" * 20), _j("sk-", "a1" * 16)],
    "Slack token": [_j("xo", "xb-", "1234567890-abc")],
    "Slack app token": [_j("xa", "pp-", "1-", "A0123456789-", "1234567890")],
    "Slack webhook URL": [
        _j("https://hooks.", "slack.com/services/", "T0000ABCD/", "B0000EFGH/", "abcdEFGH1234ijkl")
    ],
    "GitLab token": [_j("gl", "pat-", "a1B2-" * 4)],
    "Hugging Face token": [_j("h", "f_", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGH")],
    "npm access token": [_j("np", "m_", "a1" * 18)],
    "PyPI upload token": [_j("py", "pi-", "AgEI", "cHlwaS5vcmcCJ", "x" * 10)],
    "SendGrid API key": [_j("S", "G.", "a" * 22, ".", "b_" * 21, "c")],
    "DigitalOcean token": [
        _j("d", "op_v1_", "0a" * 32),
        _j("d", "oo_v1_", "f" * 64),
        _j("d", "or_v1_", "1" * 64),
    ],
    "Google API key": [_j("AI", "za", "S" * 35)],
    "Stripe live secret key": [_j("sk", "_live_", "a" * 24), _j("rk", "_live_", "B" * 24)],
    "Telegram bot token": [
        _j("1234", "56789", ":", "AA", "b-" * 16, "c"),
        _j("bot", "123456", ":", "Z_" * 17, "9"),  # inside an API URL path
        _j("x ", "987654321012", ":", "q" * 35, "/getMe"),
    ],
    "JSON private key field": [_j('"private', '_key"', ' : "x"'), _j('"private', '_key":')],
    "Private key config field": [
        _j("private", "_key: |"),  # YAML block scalar
        _j("private", "_key: >"),
        _j("private", '_key = """'),  # TOML multi-line
        _j("private", "_key = 'abc'"),
        _j("'private", "_key': 'x'"),  # single-quoted (Python/JS dict)
        _j("ssh_private", "_key: ", "MIIEvQIBADANBgkq"),
        _j("private", "_key=", "MIIEvQIBADANBgkqhkiG9w0"),
    ],
    "JSON Web Token": [
        _j("ey", "J", "hbGciOiJIUzI1NiJ9", ".", "ey", "J", "zdWIiOiIxIn0", ".", "sig_nature-abc")
    ],
}
ALL_SAMPLES = [(rule, s) for rule, samples in SAMPLES.items() for s in samples]

NEGATIVES = [
    b"ASIAN MARKETS REPORT",
    b"the AKIA prefix alone",
    b"XAKIA" + b"Q" * 16,  # glued to a longer token
    b"AKIA" + b"Q" * 17,  # too long for an access key id
    b"sk-learn is a python library",
    b"ask-" + b"a" * 40,
    b"123e4567-e89b-12d3-a456-426614174000",
    b"9fceb02d0ae598e95dc970b74767f19372d61af8",
    _j(_DASHES, "BEGIN PUBLIC KEY", _DASHES),
    _j(_DASHES, "BEGIN CERTIFICATE", _DASHES),
    b'"public_key": "abc"',
    b"private_key = 1",
    b"private_key: ${PRIVATE_KEY}",
    b"private_key_id: 'abc'",
    b"myprivate_key: 'x'",
    b"load private_key from disk",
    _j(_DASHES, "BEGIN PUBLIC KEY", _DASHES),
    b"begin private key",  # lowercase prose
    b"XBEGIN PRIVATE KEY",  # glued to a longer word
    b"glpat-short",
    b"hf_hub_download_is_a_function_name_x",
    b"x" + _j("h", "f_", "a" * 34),  # glued
    _j("h", "f_", "a" * 35),  # too long
    _j("np", "m_", "a" * 37),  # too long
    b"pypi-token",
    _j("py", "pi-", "AgEI", "short"),
    b"SG.short.x",
    _j("S", "G.", "a" * 22, ".", "b" * 10),
    _j("d", "op_v1_", "g" * 64),  # not hex
    _j("xd", "op_v1_", "0" * 64),  # glued
    b"hooks.slack.com/services/",
    b"see hooks.slack.com/services/T0/B0/x",
    b"xapp-",
    b"---- BEGIN SSH2 PUBLIC KEY ----",
    b"my_ghp_" + b"a" * 36,
    b"eyJonly.header",
    b"xoxb",
    _j("12345", ":", "a" * 35),  # bot id too short
    _j("1234567890123", ":", "a" * 35),  # bot id too long
    _j("123456789", ":", "a" * 34),  # secret part too short
    _j("123456789", ":", "a" * 36),  # ... or too long
    b"12:30:00 2026-09-26",
    b"",
]


def _scan(scanner: RegexSecretScanner, chunks: list[bytes]) -> None:
    session = scanner.new_session()
    for chunk in chunks:
        session.feed(chunk)
    session.finish()


def test_every_rule_has_samples() -> None:
    assert set(SAMPLES) == {label for label, _ in DEFAULT_RULES}


def test_labels_can_never_leak_a_token_fragment() -> None:
    # Labels are echoed to the publisher: none may match any rule, and none
    # may be a substring of any sample secret.
    scanner = RegexSecretScanner()
    for label in scanner.rule_names:
        assert " " in label
        _scan(scanner, [label.encode()])  # a label itself never matches any rule
        for _, sample in ALL_SAMPLES:
            assert label.encode() not in sample


@pytest.mark.parametrize(("rule", "sample"), ALL_SAMPLES)
def test_each_rule_detects_its_sample(rule: str, sample: bytes) -> None:
    with pytest.raises(SecretDetectedError) as info:
        _scan(RegexSecretScanner(), [b"prefix text\n" + sample + b"\nsuffix"])
    assert info.value.rule == rule


@pytest.mark.parametrize(("rule", "sample"), ALL_SAMPLES)
def test_error_never_contains_the_secret(rule: str, sample: bytes) -> None:
    with pytest.raises(SecretDetectedError) as info:
        _scan(RegexSecretScanner(), [sample])
    text = str(info.value) + repr(info.value.args)
    for i in range(len(sample) - 7):
        assert sample[i : i + 8].decode() not in text


@pytest.mark.parametrize("negative", NEGATIVES)
def test_no_false_positive_on_lookalikes(negative: bytes) -> None:
    _scan(RegexSecretScanner(), [b"x " + negative + b" y"])


@pytest.mark.parametrize(("rule", "sample"), ALL_SAMPLES)
def test_secret_split_at_every_byte_across_scan_windows(rule: str, sample: bytes) -> None:
    # block_bytes=1 forces a scan pass on every feed, so the split point is
    # also a window edge; 20 KiB of filler makes the windows actually slide.
    scanner = RegexSecretScanner(block_bytes=1)
    filler = b"." * 20_000
    for cut in range(1, len(sample)):
        with pytest.raises(SecretDetectedError) as info:
            _scan(scanner, [filler + sample[:cut], sample[cut:] + b" tail"])
        assert info.value.rule == rule


@pytest.mark.parametrize(("rule", "sample"), ALL_SAMPLES)
def test_secret_straddling_block_boundaries(rule: str, sample: bytes) -> None:
    scanner = RegexSecretScanner(block_bytes=4096)
    for shift in range(len(sample) + 1):
        data = b"." * (3 * 4096 - shift) + sample + b"." * 5
        chunks = [data[i : i + 4096] for i in range(0, len(data), 4096)]
        with pytest.raises(SecretDetectedError):
            _scan(scanner, chunks)


def test_longest_jwt_is_found_across_many_windows() -> None:
    jwt = _j("ey", "J", "a" * 4096, ".", "ey", "J", "b" * 8192, ".", "c" * 8)
    assert len(jwt) == MAX_MATCH_BYTES
    scanner = RegexSecretScanner(block_bytes=1000)
    data = b"." * 7_777 + jwt + b" end"
    chunks = [data[i : i + 997] for i in range(0, len(data), 997)]
    with pytest.raises(SecretDetectedError, match="JSON Web Token"):
        _scan(scanner, chunks)


def test_secret_at_very_start_and_very_end() -> None:
    sample = SAMPLES["AWS access key id"][0]
    with pytest.raises(SecretDetectedError):
        _scan(RegexSecretScanner(block_bytes=1), [sample])
    with pytest.raises(SecretDetectedError):
        _scan(RegexSecretScanner(block_bytes=1), [b"." * 30_000, sample])


@settings(max_examples=40, deadline=None)
@given(
    rule_sample=st.sampled_from(ALL_SAMPLES),
    before=st.integers(min_value=0, max_value=40_000),
    sizes=st.lists(st.integers(min_value=1, max_value=5_000), min_size=1, max_size=60),
)
def test_detection_is_independent_of_chunking(
    rule_sample: tuple[str, bytes], before: int, sizes: list[int]
) -> None:
    rule, sample = rule_sample
    data = b" " * before + sample + b" " * 10
    chunks: list[bytes] = []
    pos = 0
    i = 0
    while pos < len(data):
        size = sizes[i % len(sizes)]
        chunks.append(data[pos : pos + size])
        pos += size
        i += 1
    with pytest.raises(SecretDetectedError) as info:
        _scan(RegexSecretScanner(block_bytes=1_000), chunks)
    assert info.value.rule == rule


# --- ReDoS: pathological inputs stay linear ----------------------------------------------


@pytest.mark.parametrize(
    "unit",
    [
        b"eyJ",
        b"eyJ" + b"a" * 4095 + b".",
        b"eyJaaaaaaaa.eyJ",
        b"-----BEGIN ",
        b"-----BEGIN A B C D ",
        b"sk-",
        b"sk-proj-",
        b"A",
        b"AKIA",
        b"gh",
        b"xox",
        b"k_live_",
        b'"private_key"' + b" " * 16,
        b"PuTTY-User-Key-File-",
        b"BEGIN ",
        b"BEGIN A ",
        b"---- BEGIN SSH2 ",
        b"hooks.slack.com/services/aaaaaa/",
        b"hooks.slack.com/services/" + b"a" * 20,
        b"glpat-",
        b"hf_",
        b"hf_a",
        b"npm_",
        b"pypi-AgEI",
        b"SG.",
        b"SG." + b"a" * 22 + b".",
        b"dop_v1_",
        b"do",
        b"xapp-1-",
        b"private_key",
        # Split so this file's own text never matches (release export scan).
        b"private_key" + b": ",
        b"'private_key'" + b" = ",
        b"1",
        b"123456:",
        b"123456789012:",
        b"1234567:" + b"a" * 34,
    ],
)
def test_pathological_input_scans_in_linear_time(unit: bytes) -> None:
    data = unit * (4 * 1024 * 1024 // len(unit))
    start = time.perf_counter()
    with contextlib.suppress(SecretDetectedError):  # a match is fine; only time matters
        _scan(RegexSecretScanner(), [data[i : i + 65536] for i in range(0, len(data), 65536)])
    assert time.perf_counter() - start < 3.0


# --- publish path ----------------------------------------------------------------------


def _aws() -> bytes:
    return SAMPLES["AWS access key id"][0]


def test_publish_rejects_secret_split_across_chunks_and_leaves_nothing() -> None:
    h = make_publish(scanner=RegexSecretScanner())
    secret = _aws()
    data = b"hello " + secret + b" bye"
    with pytest.raises(SecretDetectedError) as info:
        h.service.publish(
            command(incoming("ok.txt", b"fine"), incoming("notes/keys.txt", data, chunk=5))
        )
    message = str(info.value)
    assert "notes/keys.txt" in message
    assert "AWS access key id" in message
    assert secret.decode() not in message
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert h.blobs.list_ids() == set()
    assert h.repo.count() == 0


@pytest.mark.parametrize("field", ["title", "description", "relpath"])
def test_publish_rejects_secret_in_metadata_before_storing(field: str) -> None:
    h = make_publish(scanner=RegexSecretScanner())
    token = _aws().decode()
    kwargs: dict[str, str] = {"title": "T", "description": ""}
    relpath = "a.txt"
    if field == "relpath":
        relpath = f"{token}.txt"
    else:
        kwargs[field] = f"see {token}"
    consumed: list[bool] = []

    def chunks() -> Iterator[bytes]:
        consumed.append(True)
        yield b"x"

    with pytest.raises(SecretDetectedError) as info:
        h.service.publish(command(IncomingFile(relpath, chunks()), **kwargs))
    assert token not in str(info.value)
    assert not consumed
    assert h.blobs.list_ids() == set()


def test_every_published_byte_goes_through_the_scanner() -> None:
    scanner = FakeContentScanner()
    h = make_publish(scanner=scanner)
    h.service.publish(command(incoming("a.bin", b"a" * 700, chunk=3), incoming("b.bin", b"b" * 5)))
    content_sessions = 2
    assert scanner.sessions == content_sessions + 1  # + the metadata session
    assert scanner.finished == scanner.sessions
    # Title and description twice (raw + sanitized), then the relpaths.
    metadata_bytes = len(b"A title\n\nA title\n\na.bin\nb.bin\n")
    assert scanner.fed_bytes == 705 + metadata_bytes


def test_lifecycle_update_rejects_secret_in_new_text() -> None:
    repo = InMemoryItemRepository()
    item = make_item(1)
    repo.add(item)
    service = LifecycleService(repo=repo, clock=FixedClock(), scanner=RegexSecretScanner())
    with pytest.raises(SecretDetectedError):
        service.update(item.id, description=f"key {_aws().decode()}")
    assert repo.get(item.id) == item


# --- metadata is scanned after sanitizing too (M1) ---------------------------------------

# Invisible chars the sanitizer strips: a token split by one of them only
# matches after sanitizing, so scanning the raw text alone would miss it.
# chr() rather than escapes or literals: the source stays plain ASCII.
_INVISIBLES = {
    "zero width space": chr(0x200B),
    "soft hyphen": chr(0x00AD),
    "word joiner": chr(0x2060),
    "byte order mark": chr(0xFEFF),
    "combining grapheme joiner": chr(0x034F),
    "mongolian vowel separator": chr(0x180E),
    "right-to-left override": chr(0x202E),
}


def _split_aws(sep: str) -> str:
    token = _aws().decode()
    return token[:2] + sep + token[2:9] + sep + token[9:]


def _kelvin_aws() -> str:
    # U+212A KELVIN SIGN is canonically equivalent to "K": NFC turns it into
    # the ASCII letter, so the stored title holds a real access key id.
    return _aws().decode().replace("K", chr(0x212A))


def _hidden_tokens() -> list[tuple[str, str]]:
    cases = [(name, _split_aws(ch)) for name, ch in _INVISIBLES.items()]
    return [*cases, ("kelvin sign NFC", _kelvin_aws())]


@pytest.mark.parametrize(("case", "token"), _hidden_tokens())
def test_hidden_token_is_really_hidden_from_a_raw_scan(case: str, token: str) -> None:
    # Guard for the tests below: the raw form must not already match.
    _scan(RegexSecretScanner(), [token.encode("utf-8")])


@pytest.mark.parametrize(("case", "token"), _hidden_tokens())
@pytest.mark.parametrize("field", ["title", "description"])
def test_publish_scans_sanitized_metadata(case: str, token: str, field: str) -> None:
    h = make_publish(scanner=RegexSecretScanner())
    kwargs = {"title": "T", "description": "", field: f"see {token} now"}
    with pytest.raises(SecretDetectedError, match="AWS access key id"):
        h.service.publish(command(incoming("a.txt", b"x"), **kwargs))
    assert h.blobs.list_ids() == set()
    assert h.repo.count() == 0


@pytest.mark.parametrize(("case", "token"), _hidden_tokens())
@pytest.mark.parametrize("field", ["title", "description"])
def test_lifecycle_update_scans_sanitized_text(case: str, token: str, field: str) -> None:
    repo = InMemoryItemRepository()
    item = make_item(1)
    repo.add(item)
    service = LifecycleService(repo=repo, clock=FixedClock(), scanner=RegexSecretScanner())
    with pytest.raises(SecretDetectedError, match="AWS access key id"):
        text = f"see {token} now"
        if field == "title":
            service.update(item.id, title=text)
        else:
            service.update(item.id, description=text)
    assert repo.get(item.id) == item
