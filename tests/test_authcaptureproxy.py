"""
Copyright 2021 Alan D. Tse.

SPDX-License-Identifier: Apache-2.0

"""

from unittest.mock import create_autospec, patch

from httpx import AsyncClient
from pytest import fixture
from yarl import URL

from authcaptureproxy import AuthCaptureProxy

HOST_URL = URL("https://www.host.com")
PROXY_URL = URL("https://www.proxy.com/proxy")


@fixture
@patch("authcaptureproxy.auth_capture_proxy.httpx.AsyncClient")
def basic_proxy(mock):
    """Return an initialized proxy object."""
    mock.return_value = create_autospec(AsyncClient)
    return AuthCaptureProxy(PROXY_URL, HOST_URL)


def test_authcaptureproxy_init(basic_proxy):
    """Test initialization of authcaptureproxy."""
    proxy = basic_proxy
    assert isinstance(proxy.session, AsyncClient)
    assert proxy._proxy_url == PROXY_URL
    assert proxy._host_url == HOST_URL
    assert proxy.port == 0
    assert proxy.runner is None
    assert proxy.last_resp is None
    assert proxy.init_query == {}
    assert proxy.query == {}
    assert proxy.data == {}
    assert proxy.headers == {}
    assert proxy.active is False
    assert proxy.all_handler_active is True
    assert proxy.tests == {}
    assert proxy.modifiers.get("text/html")
    modifiers = proxy.modifiers.get("text/html")
    for modifier in ["prepend_relative_urls", "change_host_to_proxy"]:
        assert modifier in modifiers
    assert proxy.access_url() == PROXY_URL
