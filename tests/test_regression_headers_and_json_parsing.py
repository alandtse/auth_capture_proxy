import asyncio

from typing import Any
import pytest
import httpx

from aiohttp.streams import StreamReader
from aiohttp.test_utils import make_mocked_request
from multidict import CIMultiDict
from yarl import URL


class DummyAsyncClient:
    """Capture outbound requests without real network I/O."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        # match attribute access used in logging
        self.cookies = type("Cookies", (), {"jar": {}})()

    async def aclose(self) -> None:
        return

    async def post(self, url: str, **kwargs):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "headers": dict(kwargs.get("headers") or {}),
                "json": kwargs.get("json"),
                "data": kwargs.get("data"),
            }
        )
        req = httpx.Request("POST", url)
        return httpx.Response(
            200, request=req, text="ok", headers={"Content-Type": "text/plain"}
        )


async def _make_request(
    *,
    method: str,
    path: str,
    content_type: str,
    headers=None,
    body: bytes = b"",
):
    """
    Build a mocked aiohttp Request with a real StreamReader payload.
    Request.has_body works (it calls request._payload.at_eof()).

    CI uses aiohttp 3.9.x where StreamReader requires a `limit` argument.
    """
    hdrs = CIMultiDict(headers or {})
    hdrs["Content-Type"] = content_type
    hdrs.setdefault("Content-Length", str(len(body)))

    loop = asyncio.get_running_loop()

    # aiohttp 3.9: StreamReader(protocol, limit, loop)
    # newer aiohttp: signature varies; keep this compatible.
    try:
        payload = StreamReader(None, 2**16, loop=loop)  # type: ignore[arg-type]
    except TypeError:
        payload = StreamReader(protocol=None, limit=2**16, loop=loop)  # type: ignore[arg-type]

    if body:
        payload.feed_data(body)
    payload.feed_eof()

    return make_mocked_request(method, path, headers=hdrs, payload=payload)


@pytest.fixture
def proxy(monkeypatch):
    """
    Regression note.

    These tests cover cross-request header contamination caused by in-place mutation
    of the headers mapping inside AuthCaptureProxy.all_handler().

    Specifically, the JSON request path removes proxy-related headers before sending
    the upstream request:

        for item in ["Host", "Origin", "User-Agent", "dnt", "Accept-Encoding"]:
            if req_headers.get(item):
                req_headers.pop(item)

    Prior to the fix, this mutation could occur on a shared headers dict returned
    from modify_headers(), leaking into subsequent requests. The fix copies the
    headers mapping (req_headers = dict(headers)) before mutation.

    These tests fail on the pre-fix behavior and pass once the copy is introduced.
    """
    from authcaptureproxy.auth_capture_proxy import AuthCaptureProxy

    class Proxy(AuthCaptureProxy):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.shared_headers = {
                "Host": "example.com",
                "Origin": "https://example.com",
                "User-Agent": "ua",
                "dnt": "1",
                "Accept-Encoding": "gzip",
                "X-Custom": "keep",
            }

        async def modify_headers(self, site: URL, request):  # type: ignore[override]
            # Return the same dict instance every time to expose in-place mutation leaks.
            return self.shared_headers

    p = Proxy(
        proxy_url=URL("http://127.0.0.1:12345"),
        host_url=URL("https://example.com"),
        session=DummyAsyncClient(),
    )

    # Keep output quiet and avoid side-effects not relevant to regression
    monkeypatch.setattr("authcaptureproxy.auth_capture_proxy.print_resp", lambda *_: None)

    # Keep behavior focused (tests/modifiers are unrelated to the regression)
    p._tests = {}
    p._modifiers = {}

    return p


@pytest.mark.asyncio
async def test_cross_request_header_contamination_across_json_posts(proxy):
    # JSON request #1
    req1 = await _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"a": 1}',
    )

    async def _json1():
        return {"a": 1}

    req1.json = _json1  # type: ignore[attr-defined]
    await proxy.all_handler(req1)

    # Shared dict must remain intact after request #1 (core regression assertion)
    shared = proxy.shared_headers
    assert "Host" in shared
    assert "Origin" in shared
    assert "User-Agent" in shared
    assert "dnt" in shared
    assert "Accept-Encoding" in shared
    assert shared["X-Custom"] == "keep"

    # JSON request #2
    req2 = await _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"b": 2}',
    )

    async def _json2():
        return {"b": 2}

    req2.json = _json2  # type: ignore[attr-defined]
    await proxy.all_handler(req2)

    # Both outbound requests must have proxy headers stripped
    calls = proxy.session.calls  # type: ignore[attr-defined]
    assert len(calls) >= 2
    for call in calls[-2:]:
        out = call["headers"]
        assert "Host" not in out
        assert "Origin" not in out
        assert "User-Agent" not in out
        assert "dnt" not in out
        assert "Accept-Encoding" not in out
        assert out.get("X-Custom") == "keep"


@pytest.mark.asyncio
async def test_cross_request_header_contamination_between_request_types(proxy):
    # First JSON request
    req_json = await _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"a": 1}',
    )

    async def _json():
        return {"a": 1}

    req_json.json = _json  # type: ignore[attr-defined]
    await proxy.all_handler(req_json)

    # Then a form post; provide post() to keep it on the form path.
    req_form = await _make_request(
        method="POST",
        path="/login",
        content_type="application/x-www-form-urlencoded",
        body=b"field=value",
    )

    async def _post():
        return {"field": "value"}

    req_form.post = _post  # type: ignore[attr-defined]
    await proxy.all_handler(req_form)

    form_out = proxy.session.calls[-1]["headers"]  # type: ignore[attr-defined]
    assert form_out.get("User-Agent") == "ua"
    assert form_out.get("X-Custom") == "keep"


@pytest.mark.asyncio
async def test_json_parsing_guards_on_non_json_content(proxy):
    req_form = await _make_request(
        method="POST",
        path="/login",
        content_type="application/x-www-form-urlencoded",
        body=b"field=value",
    )

    async def _json_raises():
        raise RuntimeError("json() must not be called for form posts")

    async def _post():
        return {"field": "value"}

    req_form.json = _json_raises  # type: ignore[attr-defined]
    req_form.post = _post  # type: ignore[attr-defined]

    await proxy.all_handler(req_form)


@pytest.mark.asyncio
async def test_json_parsing_for_json_content_types(proxy):
    req_json = await _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"ok": true}',
    )
    called = {"count": 0}

    async def _json():
        called["count"] += 1
        return {"ok": True}

    req_json.json = _json  # type: ignore[attr-defined]
    await proxy.all_handler(req_json)
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_json_parsing_for_json_plus_suffix_content_types(proxy):
    req_json = await _make_request(
        method="POST",
        path="/login",
        content_type="application/vnd.api+json",
        body=b'{"v": 1}',
    )
    called = {"count": 0}

    async def _json():
        called["count"] += 1
        return {"v": 1}

    req_json.json = _json  # type: ignore[attr-defined]
    await proxy.all_handler(req_json)
    assert called["count"] == 1
