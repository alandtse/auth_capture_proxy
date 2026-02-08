"""Tests for the interceptor module."""

import pytest
from unittest.mock import MagicMock
from yarl import URL

from authcaptureproxy.interceptor import BaseInterceptor, InterceptContext


PROXY_URL = URL("https://www.proxy.com/proxy")
HOST_URL = URL("https://www.host.com")


def _make_ctx(**kwargs):
    """Create an InterceptContext with mock defaults."""
    defaults = dict(
        request=MagicMock(),
        proxy=MagicMock(),
        access_url=PROXY_URL,
        host_url=HOST_URL,
        method="get",
    )
    defaults.update(kwargs)
    return InterceptContext(**defaults)


@pytest.mark.asyncio
async def test_base_interceptor_noop():
    """All BaseInterceptor hooks are callable and return None."""
    interceptor = BaseInterceptor()
    ctx = _make_ctx()
    assert await interceptor.on_request(ctx) is None
    assert await interceptor.on_request_data(ctx) is None
    assert await interceptor.on_response(ctx) is None
    assert await interceptor.on_ajax_html(ctx) is None
    assert await interceptor.on_page_html(ctx) is None


def test_intercept_context_defaults():
    """InterceptContext optional fields have correct defaults."""
    ctx = _make_ctx()
    assert ctx.site == ""
    assert ctx.data is None
    assert ctx.json_data is None
    assert ctx.response is None
    assert ctx.is_ajax is False
    assert ctx.content_type == ""
    assert ctx.body is None
    assert ctx.text is None
    assert ctx.short_circuit is None


def test_intercept_context_required_fields():
    """InterceptContext stores required fields correctly."""
    request = MagicMock()
    proxy = MagicMock()
    ctx = InterceptContext(
        request=request,
        proxy=proxy,
        access_url=PROXY_URL,
        host_url=HOST_URL,
        method="post",
    )
    assert ctx.request is request
    assert ctx.proxy is proxy
    assert ctx.access_url == PROXY_URL
    assert ctx.host_url == HOST_URL
    assert ctx.method == "post"


@pytest.mark.asyncio
async def test_custom_interceptor_override():
    """A custom interceptor can override individual hooks."""
    class TestInterceptor(BaseInterceptor):
        async def on_request(self, ctx):
            ctx.site = "https://custom.example.com/path"

    interceptor = TestInterceptor()
    ctx = _make_ctx()
    await interceptor.on_request(ctx)
    assert ctx.site == "https://custom.example.com/path"
    # Other hooks still no-op
    assert await interceptor.on_request_data(ctx) is None
    assert await interceptor.on_response(ctx) is None


@pytest.mark.asyncio
async def test_interceptor_short_circuit():
    """An interceptor can set short_circuit to return early."""
    from aiohttp import web

    class BlockingInterceptor(BaseInterceptor):
        async def on_request(self, ctx):
            ctx.short_circuit = web.Response(text="Blocked")

    interceptor = BlockingInterceptor()
    ctx = _make_ctx()
    await interceptor.on_request(ctx)
    assert ctx.short_circuit is not None
    assert ctx.short_circuit.text == "Blocked"
