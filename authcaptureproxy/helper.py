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
from typing import Any, Callable, Dict, List, Mapping, Text, Union

import httpx
from multidict import MultiDict, MultiDictProxy
from yarl import URL

_LOGGER = logging.getLogger(__name__)


def print_resp(resp: httpx.Response) -> None:
    """Print response info.

    Args:
        resp (httpx.Response): The client response to show

    Returns:
        None
    """
    if resp.history:
        for item in resp.history:
            _LOGGER.debug("%s: redirected from\n%s", item.request.method, item.url)
    url = resp.request.url
    method = resp.request.method
    status = resp.status_code
    reason = resp.reason_phrase
    headers = ast.literal_eval(str(resp.request.headers)[8:-1])
    cookies = {}
    if headers.get("cookie"):
        cookie: SimpleCookie = SimpleCookie()
        cookie.load(headers.get("cookie"))
        for key, morsel in cookie.items():
            cookies[key] = morsel.value
        headers["cookie"] = cookies
    _LOGGER.debug(
        "%s: \n%s with\n%s\nreturned %s:%s with response %s",
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
    if isinstance(old_url, str):
        old_url = URL(old_url)
    if isinstance(new_url, str):
        new_url = URL(new_url)
    if isinstance(url, str):
        url = URL(url)
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


def prepend_url(base_url: URL, url: URL, encoded: bool = False) -> URL:
    """Prepend the url.

    Args:
        base_url (URL): Base URL to prepend
        url (URL): url to prepend
        encoded (bool): Whether to treat the url as already encoded. This may be needed if the url is JavaScript.
    """
    if isinstance(base_url, str):
        base_url = URL(base_url)
    if isinstance(url, str):
        url = URL(url)
    if not url.is_absolute():
        query = url.query
        path = url.path
        return base_url.with_path(
            f"{base_url.path}{path}".replace("//", "/"), encoded=encoded
        ).with_query(query)
    return url


def replace_empty_url(new_url: URL, url: URL) -> URL:
    """Replace the empty url with new_url if and only if empty.

    Args:
        new_url (URL): New URL to use if url is blank
        url (URL): url to replace if empty
    """
    if isinstance(new_url, str):
        new_url = URL(new_url)
    if isinstance(url, str):
        url = URL(url)
    if str(url) == "":
        return new_url
    return url


def get_nested_dict_keys(
    nested_dict: Mapping[Text, Union[Callable, Dict[Text, Callable]]]
) -> List[Text]:
    """Get list of nested dict keys.

    Args:
        nested_dict (Mapping[Text, Union[Callable, Dict[Text, Callable]]]): The dictionary to parse.

    Returns:
        List[Text]: List of keys from dictionary.
    """
    result: List[Text] = []
    for key, value in nested_dict.items():
        if isinstance(value, dict):
            result += get_nested_dict_keys(value)
        else:
            result.append(key)
    return result


def get_content_type(resp: httpx.Response) -> str:
    """Get content_type from httpx Response.

    Args:
        resp (httpx.Response): Response from httpx request

    Returns:
        str: The content_type
    """
    content_type = ""
    content_type_string = resp.headers.get("content-type")
    if content_type_string and ";" in content_type_string:
        content_type = content_type_string.split(";")[0].strip()
    elif content_type_string:
        content_type = content_type_string
    return content_type


def convert_multidict_to_dict(multidict: Union[MultiDict, MultiDictProxy]) -> dict:
    """Convert a multdict to a dict for httpx.

    https://www.python-httpx.org/quickstart/#sending-form-encoded-data

    Args:
        multidict (MultiDict | MultiDictProxy): The multidict to convert

    Returns:
        dict: A dictionary where duplicate keys will be added as a list
    """
    result: dict = {}
    for k, v in multidict.items():
        old_value = result.get(k)
        if old_value:
            list_value = []
            if not isinstance(old_value, list):
                list_value.append(old_value)
            list_value.append(v)
            result[k] = list_value
        else:
            result[k] = v
    return result
