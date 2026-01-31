import pytest
import httpx

from aiohttp.test_utils import make_mocked_request
from multidict import CIMultiDict
from yarl import URL


class DummyAsyncClient:
    """Capture outbound requests without real network I/O."""

    def __init__(self) -> None:
        self.calls = []
        # mimic httpx cookies jar access used in debug logging
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
            200,
            request=req,
            text="ok",
            headers={"Content-Type": "text/plain"},
        )


class ReusedHeadersProxyMixin:
    """
    A proxy variant that intentionally returns THE SAME headers dict instance
    from modify_headers on every request.

    This is the smallest, most direct way to prove the bug your fix addresses:
    if all_handler mutates headers in-place for JSON requests, that mutation
    persists into the next request and can cause subtle/invalid header sets.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._shared_headers = {
            # include the ones JSON branch strips:
            "Host": "example.com",
            "Origin": "https://example.com",
            "User-Agent": "ua",
            "dnt": "1",
            "Accept-Encoding": "gzip",
            # include a header we must preserve:
            "X-Custom": "keep",
        }

    async def modify_headers(self, site: URL, request):  # type: ignore[override]
        # NOTE: return the exact same dict each time.
        return self._shared_headers


@pytest.fixture
def proxy(monkeypatch):
  """
  Regression note:
  
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

    class Proxy(ReusedHeadersProxyMixin, AuthCaptureProxy):
        pass

    p = Proxy(
        proxy_url=URL("http://127.0.0.1:12345"),
        host_url=URL("https://example.com"),
        session=DummyAsyncClient(),
    )

    # Make the rest of all_handler deterministic and avoid exercising
    # unrelated paths.
    monkeypatch.setattr("authcaptureproxy.auth_capture_proxy.print_resp", lambda *_: None)
    monkeypatch.setattr("authcaptureproxy.auth_capture_proxy.get_content_type", lambda *_: "text/plain")
    monkeypatch.setattr(p, "check_redirects", lambda: None)
    monkeypatch.setattr(p, "refresh_tests", lambda: None)
    monkeypatch.setattr(p, "refresh_modifiers", lambda *_: None)

    # Disable tests/modifiers so handler returns pass-through response
    p._tests = {}
    p._modifiers = {}

    return p


def _make_request(
    *,
    method: str,
    path: str,
    content_type: str,
    body: bytes = b"",
    headers: dict | None = None,
):
    hdrs = CIMultiDict(headers or {})
    # aiohttp stores content-type in headers; also expose request.content_type
    hdrs["Content-Type"] = content_type
    return make_mocked_request(
        method,
        path,
        headers=hdrs,
        payload=body,
    )


@pytest.mark.asyncio
async def test_cross_request_header_contamination_across_json_posts(proxy):
    """
    Primary regression: JSON path strips proxy-ish headers before sending.

    Before fix (no req_headers copy):
      - JSON branch pops keys from 'headers' in-place
      - because modify_headers returned a shared dict, those keys disappear
        for the next request, producing an inconsistent/invalid header set.

    After fix (req_headers = dict(headers)):
      - shared headers remain intact across requests
      - outbound request headers still have the stripped keys removed
    """
    # JSON request #1
    req1 = _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"a": 1}',
    )
    # make_mocked_request doesn't implement .json(); force the code path
    # by providing request.json via attribute.
    async def _json1():
        return {"a": 1}
    req1.json = _json1  # type: ignore[attr-defined]
    req1.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req1)

    # Shared headers must still contain the stripped keys AFTER the request.
    shared = proxy._shared_headers  # from mixin
    assert "Host" in shared
    assert "Origin" in shared
    assert "User-Agent" in shared
    assert "dnt" in shared
    assert "Accept-Encoding" in shared
    assert shared["X-Custom"] == "keep"

    # JSON request #2
    req2 = _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"b": 2}',
    )
    async def _json2():
        return {"b": 2}
    req2.json = _json2  # type: ignore[attr-defined]
    req2.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req2)

    # Outbound headers for BOTH JSON requests must have those keys removed.
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
    """
    JSON request must not "poison" the next form request by mutating shared headers.
    """
    # First JSON request triggers stripping (on a copy, after fix)
    req_json = _make_request(
        method="POST",
        path="/login",
        content_type="application/json",
        body=b'{"a": 1}',
    )
    async def _json():
        return {"a": 1}
    req_json.json = _json  # type: ignore[attr-defined]
    req_json.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req_json)

    # Next form request should still have full shared headers available
    req_form = _make_request(
        method="POST",
        path="/login",
        content_type="application/x-www-form-urlencoded",
        body=b"field=value",
        headers={"Content-Length": "11"},
    )
    async def _post():
        return {"field": "value"}
    req_form.post = _post  # type: ignore[attr-defined]
    req_form.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req_form)

    # For form posts, the JSON stripping logic does not run.
    form_out = proxy.session.calls[-1]["headers"]  # type: ignore[attr-defined]
    assert form_out.get("User-Agent") == "ua"
    assert form_out.get("X-Custom") == "keep"


@pytest.mark.asyncio
async def test_json_parsing_guards_on_non_json_content(proxy):
    """
    Regression: JSON parsing must NOT be attempted for form posts.

    Before fix: if code unconditionally calls request.json() when has_body,
    this will raise and break processing.
    After fix: request.json() is only called for JSON content-types.
    """
    req_form = _make_request(
        method="POST",
        path="/login",
        content_type="application/x-www-form-urlencoded",
        body=b"field=value",
    )
    # If handler calls json() on a form post, explode
    async def _json_raises():
        raise RuntimeError("json() should not be called for form posts")
    req_form.json = _json_raises  # type: ignore[attr-defined]
    async def _post():
        return {"field": "value"}
    req_form.post = _post  # type: ignore[attr-defined]
    req_form.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req_form)


@pytest.mark.asyncio
async def test_json_parsing_only_for_json_content_types(proxy):
    req_json = _make_request(
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
    req_json.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req_json)
    assert called["count"] == 1


@pytest.mark.asyncio
async def test_json_parsing_for_json_plus_suffix_content_types(proxy):
    req_json = _make_request(
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
    req_json.has_body = True  # type: ignore[attr-defined]

    await proxy.all_handler(req_json)
    assert called["count"] == 1
