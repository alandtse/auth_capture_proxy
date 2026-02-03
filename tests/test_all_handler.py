"""Tests for the all_handler interceptor pipeline."""

from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

import httpx
import pytest
from aiohttp import web
from httpx import AsyncClient
from multidict import CIMultiDict
from yarl import URL

from authcaptureproxy import AuthCaptureProxy
from authcaptureproxy.interceptor import BaseInterceptor, InterceptContext

HOST_URL = URL("https://www.host.com")
PROXY_URL = URL("https://www.proxy.com/proxy")


def _make_proxy():
    """Create a proxy with mocked httpx session."""
    with patch("authcaptureproxy.auth_capture_proxy.httpx.AsyncClient"):
        proxy = AuthCaptureProxy(PROXY_URL, HOST_URL)
    mock_session = create_autospec(AsyncClient, instance=True)
    proxy.session = mock_session
    return proxy, mock_session


def _make_request(path="/proxy/some/page", method="GET", headers=None, query_string=""):
    """Create a mock aiohttp web.Request."""
    req = MagicMock(spec=web.Request)
    req.method = method
    url = URL(f"https://www.proxy.com{path}")
    req.url = url
    req.scheme = "https"
    req.content_type = "application/x-www-form-urlencoded"
    req.has_body = False
    req.query_string = query_string
    req.query = {}
    _headers = CIMultiDict(headers or {})
    # Add Sec-Fetch-Mode=navigate for page requests by default
    if "Sec-Fetch-Mode" not in _headers:
        _headers["Sec-Fetch-Mode"] = "navigate"
    req.headers = _headers
    # Mock post() to return empty dict
    req.post = AsyncMock(return_value=CIMultiDict())
    return req


def _make_response(text="<html><body>Hello</body></html>", status_code=200, url=None):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode("utf-8") if text else b""
    resp.url = httpx.URL(url or "https://www.host.com/some/page")
    resp.history = []
    resp.headers = {"content-type": "text/html; charset=utf-8"}
    resp.request = MagicMock()
    resp.request.url = resp.url
    resp.request.method = "GET"
    resp.request.headers = httpx.Headers({"host": "www.host.com"})
    resp.reason_phrase = "OK"
    return resp


@pytest.mark.asyncio
async def test_handler_no_interceptors():
    """Basic GET proxies correctly without interceptors."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731
    req = _make_request()
    resp = _make_response()
    mock_session.get = AsyncMock(return_value=resp)

    result = await proxy.all_handler(req)
    assert result.status == 200
    mock_session.get.assert_called_once()


@pytest.mark.asyncio
async def test_handler_interceptor_sets_site():
    """on_request sets ctx.site, skips generic URL resolution."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731

    class CustomRouter(BaseInterceptor):
        async def on_request(self, ctx):
            ctx.site = "https://custom.example.com/api"

    proxy.interceptors = [CustomRouter()]
    req = _make_request()
    resp = _make_response(url="https://custom.example.com/api")
    mock_session.get = AsyncMock(return_value=resp)

    await proxy.all_handler(req)
    # Verify the custom URL was used
    call_args = mock_session.get.call_args
    assert "custom.example.com" in call_args[0][0]


@pytest.mark.asyncio
async def test_handler_interceptor_short_circuits_request():
    """on_request sets ctx.short_circuit, returns early."""
    proxy, mock_session = _make_proxy()

    class BlockInterceptor(BaseInterceptor):
        async def on_request(self, ctx):
            ctx.short_circuit = web.Response(text="Blocked by interceptor")

    proxy.interceptors = [BlockInterceptor()]
    req = _make_request()
    # Explicitly set get to raise if called (should never happen)
    mock_session.get = AsyncMock(side_effect=AssertionError("HTTP request should not be made"))

    result = await proxy.all_handler(req)
    assert result.text == "Blocked by interceptor"


@pytest.mark.asyncio
async def test_handler_interceptor_modifies_data():
    """on_request_data modifies POST data before forwarding."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731

    class DataModifier(BaseInterceptor):
        async def on_request_data(self, ctx):
            if ctx.data and "password" in ctx.data:
                ctx.data["extra_field"] = "injected"

    proxy.interceptors = [DataModifier()]
    req = _make_request(method="POST")
    req.has_body = True
    req.post = AsyncMock(return_value=CIMultiDict({"password": "test123"}))
    resp = _make_response()
    mock_session.post = AsyncMock(return_value=resp)

    await proxy.all_handler(req)
    call_args = mock_session.post.call_args
    sent_data = call_args.kwargs.get("data") or call_args[1].get("data")
    assert sent_data["extra_field"] == "injected"


@pytest.mark.asyncio
async def test_handler_interceptor_modifies_ajax_html():
    """on_ajax_html modifies AJAX response body."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731

    class AjaxModifier(BaseInterceptor):
        async def on_ajax_html(self, ctx):
            if ctx.body:
                ctx.body = b"<html>Modified AJAX</html>"

    proxy.interceptors = [AjaxModifier()]
    req = _make_request()
    req.headers = CIMultiDict({"Sec-Fetch-Mode": "cors"})
    resp = _make_response()
    mock_session.get = AsyncMock(return_value=resp)

    result = await proxy.all_handler(req)
    assert b"Modified AJAX" in result.body


@pytest.mark.asyncio
async def test_handler_interceptor_modifies_page_html():
    """on_page_html injects content before modifiers."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731

    class PageModifier(BaseInterceptor):
        async def on_page_html(self, ctx):
            if ctx.text:
                ctx.text = ctx.text.replace("</body>", "<p>Injected</p></body>")

    proxy.interceptors = [PageModifier()]
    req = _make_request()
    resp = _make_response(text="<html><body>Original</body></html>")
    mock_session.get = AsyncMock(return_value=resp)

    result = await proxy.all_handler(req)
    assert "Injected" in result.text


@pytest.mark.asyncio
async def test_handler_interceptor_short_circuits_response():
    """on_response sets ctx.short_circuit."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731

    class ResponseBlocker(BaseInterceptor):
        async def on_response(self, ctx):
            if ctx.response and ctx.response.status_code == 403:
                ctx.short_circuit = web.Response(text="Forbidden", status=403)

    proxy.interceptors = [ResponseBlocker()]
    req = _make_request()
    resp = _make_response(status_code=403)
    mock_session.get = AsyncMock(return_value=resp)

    result = await proxy.all_handler(req)
    assert result.status == 403
    assert result.text == "Forbidden"


@pytest.mark.asyncio
async def test_handler_multiple_interceptors_order():
    """Multiple interceptors run in registration order."""
    proxy, mock_session = _make_proxy()
    proxy._tests = {"dummy": lambda resp, data, query: None}  # noqa: E731
    call_order = []

    class First(BaseInterceptor):
        async def on_request(self, ctx):
            call_order.append("first")

    class Second(BaseInterceptor):
        async def on_request(self, ctx):
            call_order.append("second")

    proxy.interceptors = [First(), Second()]
    req = _make_request()
    resp = _make_response()
    mock_session.get = AsyncMock(return_value=resp)

    await proxy.all_handler(req)
    assert call_order == ["first", "second"]
