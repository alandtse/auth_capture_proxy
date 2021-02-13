#  SPDX-License-Identifier: Apache-2.0
"""
Python Package for auth capture proxy.

Helper files.
"""
import json
import logging
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, Text

from aiohttp import ClientResponse
from yarl import URL

_LOGGER = logging.getLogger(__name__)


def print_resp(resp: ClientResponse) -> None:
    """Print response info.

    Args:
        resp (ClientResponse): The client response to show

    Returns:
        None
    """
    if resp.history:
        for item in resp.history:
            _LOGGER.debug("%s: redirected from\n%s", item.method, item.url)
    url = resp.request_info.url
    method = resp.request_info.method
    status = resp.status
    reason = resp.reason
    headers = eval(
        str(resp.request_info.headers).replace("<CIMultiDictProxy(", "{").replace(")>", "}")
    )
    cookies = {}
    if headers.get("Cookie"):
        cookie = SimpleCookie()
        cookie.load(headers.get("Cookie"))
        for key, morsel in cookie.items():
            cookies[key] = morsel.value
        headers["Cookie"] = cookies
    _LOGGER.debug(
        "%s: \n%s with\n%s\n returned %s:%s with response %s",
        method,
        url,
        json.dumps(headers),
        status,
        reason,
        resp.headers,
    )


def prepend_url(base_url: URL, url: URL) -> URL:
    """Prepend the url.

    Args:
        base_url (URL): Base URL to prepend
        url (URL): url to prepend
    """
    for arg in [base_url, url]:
        if isinstance(arg, str):
            arg = URL(arg)
    if not url.is_absolute():
        query = url.query
        path = url.path
        return base_url.with_path(f"{base_url.path}{path}".replace("//", "/")).with_query(query)
    return url
