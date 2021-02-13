#  SPDX-License-Identifier: Apache-2.0
"""
Python Package for auth capture proxy.

Helper files.
"""
import ast
import json
import logging
from asyncio import iscoroutinefunction
from http.cookies import SimpleCookie
from typing import Any, Callable, Text
from multidict import MultiDict
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
    headers = ast.literal_eval(
        str(resp.request_info.headers).replace("<CIMultiDictProxy(", "{").replace(")>", "}")
    )
    cookies = {}
    if headers.get("Cookie"):
        cookie: SimpleCookie = SimpleCookie()
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


async def run_func(func: Callable, name: Text = "", *args, **kwargs) -> Any:
    """Run any function or coroutine.

    Args:
        func (Callable): Func to run
        name (Text, optional): Name for function. Defaults to "".

    Returns:
        Any: Result of running the function
    """
    result = None
    unknown_name = repr(func)
    if name:
        name = name
    else:
        try:
            # get function name
            name = func.__name__
        except AttributeError:
            # check partial
            try:
                name = func.func.__name__  # type: ignore[attr-defined]
            except AttributeError:
                # unknown
                name = unknown_name
    if iscoroutinefunction(func) or getattr(func, "func", None) and iscoroutinefunction(func.func):  # type: ignore[attr-defined]
        _LOGGER.debug("Running coroutine %s", name)
        result = await func(*args, **kwargs)
    else:
        _LOGGER.debug("Running function %s", name)
        result = func(*args, **kwargs)
    return result


def swap_url(
    ignore_query: bool = True,
    old_url: URL = URL(""),  # noqa: B008
    new_url: URL = URL(""),  # noqa: B008
    url: URL = URL(""),  # noqa: B008
) -> URL:
    """Swap any instances of the old url with the new url. Will not replace query info.

    Args:
        ignore_query (bool): Whether the url.query should be ignored. Defaults to True.
        old_url (URL): Old url to find and replace. If there is any additional path, it will be added to the new_url.
        new_url (URL): New url to replace.
        url (URL): url to modify
    """
    for arg in [old_url, new_url, url]:
        if isinstance(arg, str):
            arg = URL(arg)
    old_url_string: Text = str(old_url.with_query({}))
    new_url_string: Text = str(new_url.with_query({}))
    old_query: MultiDict = url.query
    url_string = str(url.with_query({}))
    # ensure both paths end with "/" if one of them does
    if (
        new_url_string
        and new_url_string[-1] == "/"
        and old_url_string
        and old_url_string[-1] != "/"
    ):
        old_url_string += "/"
    elif (
        old_url_string
        and old_url_string[-1] == "/"
        and new_url_string
        and new_url_string[-1] != "/"
    ):
        new_url_string += "/"
    if ignore_query:
        result = URL(url_string.replace(old_url_string, new_url_string))
        # clean up any // in path
        return result.with_path(result.path.replace("//", "/")).with_query(old_query)
    new_query = {}
    for key, value in old_query.items():
        if value:
            new_query[key] = value.replace(old_url_string, new_url_string)
    result = URL(url_string.replace(old_url_string, new_url_string))
    return result.with_path(result.path.replace("//", "/")).update_query(new_query)


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
