"""Tests for the Amazon WAF interceptor."""

import base64
import json
from unittest.mock import MagicMock

import httpx
import pytest
from aiohttp import web
from yarl import URL

from authcaptureproxy.examples.amazon_waf import AmazonWAFInterceptor
from authcaptureproxy.interceptor import InterceptContext

HOST_URL = URL("https://www.amazon.it")
PROXY_URL = URL("https://192.168.1.100:8123/auth/proxy")


def _make_ctx(**kwargs):
    """Create an InterceptContext with Amazon-like defaults."""
    proxy = MagicMock()
    proxy._host_url = HOST_URL
    proxy._build_response = MagicMock(side_effect=lambda **kw: _async_response(kw.get("text", "")))
    defaults = dict(
        request=MagicMock(),
        proxy=proxy,
        access_url=PROXY_URL,
        host_url=HOST_URL,
        method="get",
    )
    defaults.update(kwargs)
    return InterceptContext(**defaults)


async def _async_response(text):
    """Helper to create a web.Response from async mock."""
    return web.Response(text=text)


# --- on_request tests ---


@pytest.mark.asyncio
async def test_on_request_amzn_host_routing():
    """__amzn_host__ marker routes to correct host."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/__amzn_host__fls-eu.amazon.it/1/batch/1")
    req.query_string = ""
    ctx = _make_ctx(request=req)

    await interceptor.on_request(ctx)
    assert ctx.site == "https://fls-eu.amazon.it/1/batch/1"
    assert ctx.short_circuit is None


@pytest.mark.asyncio
async def test_on_request_amzn_host_with_query():
    """__amzn_host__ routing preserves query string."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/__amzn_host__fls-eu.amazon.it/path")
    req.query_string = "key=value&other=1"
    ctx = _make_ctx(request=req)

    await interceptor.on_request(ctx)
    assert ctx.site == "https://fls-eu.amazon.it/path?key=value&other=1"


@pytest.mark.asyncio
async def test_on_request_blocked_host():
    """Non-Amazon host returns short_circuit error."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/__amzn_host__evil.example.com/steal")
    req.query_string = ""
    ctx = _make_ctx(request=req)

    await interceptor.on_request(ctx)
    assert ctx.short_circuit is not None


@pytest.mark.asyncio
async def test_on_request_awswaf_allowed():
    """awswaf.com hosts are allowed through."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL(
        "https://192.168.1.100:8123/auth/proxy/__amzn_host__abc123.token.awswaf.com/verify"
    )
    req.query_string = ""
    ctx = _make_ctx(request=req)

    await interceptor.on_request(ctx)
    assert ctx.site == "https://abc123.token.awswaf.com/verify"
    assert ctx.short_circuit is None


@pytest.mark.asyncio
async def test_on_request_no_marker():
    """Normal request without marker: ctx.site stays empty."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/ap/signin")
    req.query_string = ""
    ctx = _make_ctx(request=req)

    await interceptor.on_request(ctx)
    assert ctx.site == ""
    assert ctx.short_circuit is None


# --- on_request_data tests ---


@pytest.mark.asyncio
async def test_on_request_data_valid_aamation():
    """Valid base64 aamation token is forwarded as-is."""
    interceptor = AmazonWAFInterceptor()
    # Create a valid base64-encoded JSON token
    token_data = json.dumps({"sessionToken": "abc123"}).encode()
    valid_token = base64.urlsafe_b64encode(token_data).decode().rstrip("=")

    proxy = MagicMock()
    proxy._login = MagicMock()
    ctx = _make_ctx(
        proxy=proxy,
        site="/ap/cvf/verify",
        data={
            "cvf_aamation_response_token": valid_token,
            "cvf_aamation_error_code": "",
            "cvf_captcha_captcha_action": "verifyAamationChallenge",
        },
    )

    await interceptor.on_request_data(ctx)
    # Token should not be cleared
    assert ctx.data["cvf_aamation_response_token"] == valid_token


@pytest.mark.asyncio
async def test_on_request_data_invalid_aamation_with_totp():
    """Invalid aamation token is cleared and TOTP injected."""
    interceptor = AmazonWAFInterceptor()
    proxy = MagicMock()
    proxy._login = MagicMock()
    proxy._login.get_totp_token = MagicMock(return_value="123456")
    ctx = _make_ctx(
        proxy=proxy,
        site="/ap/cvf/verify",
        data={
            "cvf_aamation_response_token": "invalid_not_base64",  # nosec B105
            "cvf_aamation_error_code": "NetworkError",
            "cvf_captcha_captcha_action": "",
        },
    )

    await interceptor.on_request_data(ctx)
    assert ctx.data["cvf_aamation_response_token"] == ""
    assert ctx.data["cvf_aamation_error_code"] == ""
    assert ctx.data["otpCode"] == "123456"
    assert ctx.data["rememberDevice"] == "true"


@pytest.mark.asyncio
async def test_on_request_data_invalid_aamation_no_totp():
    """Invalid aamation without TOTP: fields cleared, no OTP."""
    interceptor = AmazonWAFInterceptor()
    proxy = MagicMock()
    proxy._login = MagicMock(spec=[])  # No get_totp_token
    ctx = _make_ctx(
        proxy=proxy,
        site="/ap/cvf/verify",
        data={
            "cvf_aamation_response_token": "bad",  # nosec B105
            "cvf_aamation_error_code": "err",
            "cvf_captcha_captcha_action": "x",
        },
    )

    await interceptor.on_request_data(ctx)
    assert ctx.data["cvf_aamation_response_token"] == ""
    assert "otpCode" not in ctx.data


@pytest.mark.asyncio
async def test_on_request_data_non_cvf():
    """Non-CVF POST: no modification to data."""
    interceptor = AmazonWAFInterceptor()
    proxy = MagicMock()
    proxy._login = MagicMock()
    original_data = {"email": "user@test.com", "password": "secret"}  # nosec B105
    ctx = _make_ctx(
        proxy=proxy,
        site="/ap/some/other/page",
        data=dict(original_data),
    )

    await interceptor.on_request_data(ctx)
    assert ctx.data == original_data


@pytest.mark.asyncio
async def test_on_request_data_no_data():
    """No data: interceptor returns without error."""
    interceptor = AmazonWAFInterceptor()
    ctx = _make_ctx(site="/ap/cvf/verify", data=None)
    await interceptor.on_request_data(ctx)
    assert ctx.data is None


# --- on_response tests ---


@pytest.mark.asyncio
async def test_on_response_cvf_detection():
    """CVF page detected and logged without error."""
    interceptor = AmazonWAFInterceptor()
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.url = httpx.URL("https://www.amazon.it/ap/cvf/request")
    proxy = MagicMock()
    proxy._login = MagicMock()
    ctx = _make_ctx(proxy=proxy, response=resp)

    # Should not raise
    await interceptor.on_response(ctx)
    assert ctx.short_circuit is None


@pytest.mark.asyncio
async def test_on_response_no_login():
    """Without _login, on_response is a no-op."""
    interceptor = AmazonWAFInterceptor()
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.url = httpx.URL("https://www.amazon.it/ap/cvf/request")
    proxy = MagicMock(spec=[])  # No _login attribute
    ctx = _make_ctx(proxy=proxy, response=resp)

    await interceptor.on_response(ctx)
    assert ctx.short_circuit is None


# --- on_ajax_html tests ---


@pytest.mark.asyncio
async def test_on_ajax_html_aaut_injection():
    """P shim injected into /aaut/verify/cvf response."""
    interceptor = AmazonWAFInterceptor()
    html = (
        "<html><head></head><body>"
        '<script src="https://abc.token.awswaf.com/captcha.js"></script>'
        "</body></html>"
    )
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/aaut/verify/cvf")
    resp = MagicMock(spec=httpx.Response)
    resp.content = html.encode("utf-8")
    ctx = _make_ctx(request=req, response=resp, body=html.encode("utf-8"))

    await interceptor.on_ajax_html(ctx)
    decoded = ctx.body.decode("utf-8")
    # P shim should be injected
    assert "window.P=window.P||" in decoded
    # AJAX proxy should be injected
    assert "__amzn_host__" in decoded
    # awswaf script src should be rewritten to proxy
    assert "https://abc.token.awswaf.com/" not in decoded


@pytest.mark.asyncio
async def test_on_ajax_html_non_aaut():
    """Non-aaut AJAX: body unchanged."""
    interceptor = AmazonWAFInterceptor()
    original_body = b"<html>Not aaut</html>"
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/ap/signin")
    ctx = _make_ctx(request=req, body=original_body)

    await interceptor.on_ajax_html(ctx)
    assert ctx.body == original_body


@pytest.mark.asyncio
async def test_on_ajax_html_no_body():
    """Empty body: interceptor returns without error."""
    interceptor = AmazonWAFInterceptor()
    req = MagicMock()
    req.url = URL("https://192.168.1.100:8123/auth/proxy/aaut/verify/cvf")
    ctx = _make_ctx(request=req, body=None)

    await interceptor.on_ajax_html(ctx)
    assert ctx.body is None


# --- on_page_html tests ---


@pytest.mark.asyncio
async def test_on_page_html_cvf_injection():
    """Submit blocker + AJAX proxy injected into CVF page."""
    interceptor = AmazonWAFInterceptor()
    html = "<html><head><script>var x=1;</script></head><body>CVF</body></html>"
    resp = MagicMock(spec=httpx.Response)
    resp.url = httpx.URL("https://www.amazon.it/ap/cvf/request")
    ctx = _make_ctx(response=resp, text=html, content_type="text/html")

    await interceptor.on_page_html(ctx)
    # Submit blocker should be injected
    assert "_origSubmit" in ctx.text
    assert "CAPTCHA" in ctx.text
    # AJAX proxy should be injected
    assert "__amzn_host__" in ctx.text
    # Original content preserved
    assert "var x=1;" in ctx.text


@pytest.mark.asyncio
async def test_on_page_html_non_cvf():
    """Non-CVF page: text unchanged."""
    interceptor = AmazonWAFInterceptor()
    html = "<html><head><script>var x=1;</script></head><body>Signin</body></html>"
    resp = MagicMock(spec=httpx.Response)
    resp.url = httpx.URL("https://www.amazon.it/ap/signin")
    ctx = _make_ctx(response=resp, text=html, content_type="text/html")

    await interceptor.on_page_html(ctx)
    assert ctx.text == html


@pytest.mark.asyncio
async def test_on_page_html_no_response():
    """No response: interceptor returns without error."""
    interceptor = AmazonWAFInterceptor()
    ctx = _make_ctx(response=None, text="<html>test</html>")

    await interceptor.on_page_html(ctx)
    assert ctx.text == "<html>test</html>"


@pytest.mark.asyncio
async def test_on_page_html_no_text():
    """Empty text: interceptor returns without error."""
    interceptor = AmazonWAFInterceptor()
    resp = MagicMock(spec=httpx.Response)
    resp.url = httpx.URL("https://www.amazon.it/ap/cvf/request")
    ctx = _make_ctx(response=resp, text="")

    await interceptor.on_page_html(ctx)
    assert ctx.text == ""
