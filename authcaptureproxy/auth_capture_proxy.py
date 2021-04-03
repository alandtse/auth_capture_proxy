#  SPDX-License-Identifier: Apache-2.0
"""Python Package for auth capture proxy."""
import asyncio
import logging
import re
from functools import partial
from ssl import SSLContext
from typing import Any, Callable, Dict, List, Optional, Text, Tuple, Union

import multidict
from aiohttp import (
    ClientConnectionError,
    ClientSession,
    ClientTimeout,
    MultipartReader,
    MultipartWriter,
    TooManyRedirects,
    hdrs,
    web,
)
from aiohttp.client_reqrep import ClientResponse
from yarl import URL

from authcaptureproxy.const import SKIP_AUTO_HEADERS
from authcaptureproxy.examples.modifiers import (
    prepend_relative_urls,
    replace_empty_action_urls,
    replace_matching_urls,
)
from authcaptureproxy.helper import get_nested_dict_keys, print_resp, run_func, swap_url
from authcaptureproxy.stackoverflow import get_open_port

_LOGGER = logging.getLogger(__name__)


class AuthCaptureProxy:
    """Class to handle proxy login connections.

    This class relies on tests to be provided to indicate the proxy has completed. At proxy completion all data can be found in self.session, self.data, and self.query.
    """

    def __init__(
        self, proxy_url: URL, host_url: URL, session: Optional[ClientSession] = None
    ) -> None:
        """Initialize proxy object.

        Args:
            proxy_url (URL): url for proxy location. e.g., http://192.168.1.1/. If there is any path, the path is considered part of the base url. If no explicit port is specified, a random port will be generated. If https is passed in, ssl_context must be provided at start_proxy() or the url will be downgraded to http.
            host_url (URL): original url for login, e.g., http://amazon.com
            session (ClientSession): Session to make aiohttp queries. Optional

        """
        self.session: ClientSession = (
            session if session else ClientSession(timeout=ClientTimeout(total=30))
        )
        self._proxy_url: URL = proxy_url
        self._host_url: URL = host_url
        self._port: int = proxy_url.explicit_port if proxy_url.explicit_port else 0  # type: ignore
        self.runner: Optional[web.AppRunner] = None
        self.last_resp: Optional[ClientResponse] = None
        self.init_query: Dict[Text, Any] = {}
        self.query: Dict[Text, Any] = {}
        self.data: Dict[Text, Any] = {}
        # tests and modifiers should be initialized after port is actually assigned and not during init.
        # however, to ensure defaults go first, they should have a dummy key set
        self._tests: Dict[Text, Callable] = {}
        self._modifiers: Dict[Text, Union[Callable, Dict[Text, Callable]]] = {
            "text/html": {
                "prepend_relative_urls": lambda x: x,
                "change_host_to_proxy": lambda x: x,
            }
        }
        self._old_tests: Dict[Text, Callable] = {}
        self._old_modifiers: Dict[Text, Union[Callable, Dict[Text, Callable]]] = {}
        self._active = False
        self._all_handler_active = True
        self.headers: Dict[Text, Text] = {}
        self.redirect_filters: Dict[Text, List[Text]] = {
            "url": []
        }  # dictionary of lists of regex strings to filter against

    @property
    def active(self) -> bool:
        """Return whether proxy is started."""
        return self._active

    @property
    def all_handler_active(self) -> bool:
        """Return whether all handler is active."""
        return self._all_handler_active

    @all_handler_active.setter
    def all_handler_active(self, value: bool) -> None:
        """Set all handler to value."""
        self._all_handler_active = value

    @property
    def port(self) -> int:
        """Return port setting."""
        return self._port

    @property
    def tests(self) -> Dict[Text, Callable]:
        """Return tests setting.

        :setter: value (Dict[Text, Any]): A dictionary of tests. The key should be the name of the test and the value should be a function or coroutine that takes a ClientResponse, a dictionary of post variables, and a dictioary of query variables and returns a URL or string. See :mod:`authcaptureproxy.examples.testers` for examples.
        """
        return self._tests

    @tests.setter
    def tests(self, value: Dict[Text, Callable]) -> None:
        """Set tests.

        Args:
            value (Dict[Text, Any]): A dictionary of tests.
        """
        self.refresh_tests()  # refresh in case of pending change
        self._old_tests = self._tests.copy()
        self._tests = value

    @property
    def modifiers(self) -> Dict[Text, Union[Callable, Dict[Text, Callable]]]:
        """Return modifiers setting.

        :setter: value (Dict[Text, Dict[Text, Callable]): A nested dictionary of modifiers. The key shoud be a MIME type and the value should be a dictionary of modifiers for that MIME type where the key should be the name of the modifier and the value should be a function or couroutine that takes a string and returns a modified string. If parameters are necessary, functools.partial should be used. See :mod:`authcaptureproxy.examples.modifiers` for examples.
        """
        return self._modifiers

    @modifiers.setter
    def modifiers(self, value: Dict[Text, Union[Callable, Dict[Text, Callable]]]) -> None:
        """Set tests.

        Args:
            value (Dict[Text, Any]): A dictionary of tests.
        """
        self.refresh_modifiers()  # refresh in case of pending change
        self._old_modifiers = self._modifiers
        self._modifiers = value

    def access_url(self) -> URL:
        """Return access url for proxy with port."""
        return self._proxy_url.with_port(self.port)

    async def change_host_url(self, new_url: URL) -> None:
        """Change the host url of the proxy.

        This will also reset all stored data.

        Args:
            new_url (URL): original url for login, e.g., http://amazon.com
        """
        if not isinstance(new_url, URL):
            raise ValueError("URL required")
        self._host_url = new_url
        await self.reset_data()

    async def reset_data(self) -> None:
        """Reset all stored data.

        A proxy may need to service multiple login requests if the route is not torn down. This function will reset all data between logins.
        """
        if self.session and not self.session.closed:
            if self.session._connector_owner and self.session._connector:
                await self.session._connector.close()
            self.session._connector = None
        self.session = ClientSession()
        self.last_resp = None
        self.init_query = {}
        self.query = {}
        self.data = {}
        self._active = False
        self._all_handler_active = True
        _LOGGER.debug("Proxy data reset.")

    def refresh_tests(self) -> None:
        """Refresh tests.

        Because tests may use partials, they will freeze their parameters which is a problem with self.access() if the port hasn't been assigned.
        """
        if self._tests != self._old_tests:
            self.tests.update({})
            self.old_tests = self.tests.copy()
            _LOGGER.debug("Refreshed %s tests: %s", len(self.tests), list(self.tests.keys()))

    def refresh_modifiers(self, site: Optional[URL] = None) -> None:
        """Refresh modifiers.

        Because modifiers may use partials, they will freeze their parameters which is a problem with self.access() if the port hasn't been assigned.

        Args:
            site (Optional[URL], optional): The current site. Defaults to None.
        """
        DEFAULT_MODIFIERS = {
            "prepend_relative_urls": partial(prepend_relative_urls, self.access_url()),
            "change_host_to_proxy": partial(
                replace_matching_urls,
                self._host_url.with_query({}).with_path("/"),
                self.access_url(),
            ),
        }
        if self._modifiers != self._old_modifiers:
            if self.modifiers.get("text/html") is None:
                self.modifiers["text/html"] = DEFAULT_MODIFIERS  # type: ignore
            elif self.modifiers.get("text/html") and isinstance(self.modifiers["text/html"], dict):
                self.modifiers["text/html"].update(DEFAULT_MODIFIERS)
            if site and isinstance(self.modifiers["text/html"], dict):
                self.modifiers["text/html"].update(
                    {
                        "change_empty_to_proxy": partial(
                            replace_empty_action_urls,
                            swap_url(
                                old_url=self._host_url.with_query({}),
                                new_url=self.access_url().with_query({}),
                                url=site,
                            ),
                        ),
                    }
                )
            self._old_modifiers = self.modifiers.copy()
            refreshed_modifers = get_nested_dict_keys(self.modifiers)
            _LOGGER.debug("Refreshed %s modifiers: %s", len(refreshed_modifers), refreshed_modifers)

    async def all_handler(self, request: web.Request, **kwargs) -> web.Response:
        """Handle all requests.

        This handler will exit on succesful test found in self.tests or if a /stop url is seen. This handler can be used with any aiohttp webserver and disabled after registered using self.all_handler_active.

        Args
            request (web.Request): The request to process

        Returns
            web.Response: The webresponse to the browser

        Raises
            web.HTTPFound: Redirect URL upon success
            web.HTTPNotFound: Return 404 when all_handler is disabled

        """

        async def _process_multipart(reader: MultipartReader, writer: MultipartWriter) -> None:
            """Process multipart.

            Args:
                reader (MultipartReader): Response multipart to process.
                writer (MultipartWriter): Multipart to write out.
            """
            while True:
                part = await reader.next()  # noqa: B305
                # https://github.com/PyCQA/flake8-bugbear/issues/59
                if part is None:
                    break
                if isinstance(part, MultipartReader):
                    await _process_multipart(part, writer)
                elif part.headers.get("hdrs.CONTENT_TYPE"):
                    if part.headers[hdrs.CONTENT_TYPE] == "application/json":
                        part_data: Optional[
                            Union[Text, Dict[Text, Any], List[Tuple[Text, Text]], bytes]
                        ] = await part.json()
                        writer.append_json(part_data)
                    elif part.headers[hdrs.CONTENT_TYPE].startswith("text"):
                        part_data = await part.text()
                        writer.append(part_data)
                    elif part.headers[hdrs.CONTENT_TYPE] == "application/www-urlform-encode":
                        part_data = await part.form()
                        writer.append_form(part_data)
                    else:
                        part_data = await part.read()
                        writer.append(part_data)
                else:
                    part_data = await part.read()
                    if part.name:
                        self.data.update({part.name: part_data})
                    elif part.filename:
                        part_data = await part.read()
                        self.data.update({part.filename: part_data})
                    writer.append(part_data)

        if not self.all_handler_active:
            _LOGGER.debug("%s all_handler is disabled; returning 404.", self)
            raise web.HTTPNotFound()
        if not self.session:
            self.session = ClientSession()
        method = request.method.lower()
        _LOGGER.debug("Received %s: %s for %s", method, request.url, self._host_url)
        resp: Optional[ClientResponse] = None
        old_url: URL = (
            self.access_url().with_host(request.url.host)
            if request.url.host and request.url.host != self.access_url().host
            else self.access_url()
        )
        if request.scheme == "http" and self.access_url().scheme == "https":
            # detect reverse proxy downgrade
            _LOGGER.debug("Detected http while should be https; switching to https")
            site: URL = swap_url(
                ignore_query=True,
                old_url=old_url,
                new_url=self._host_url.with_path("/"),
                url=request.url.with_scheme("https"),
            )
        else:
            site = swap_url(
                ignore_query=True,
                old_url=old_url,
                new_url=self._host_url.with_path("/"),
                url=request.url,
            )
        self.query.update(request.query)
        data = None
        mpwriter = None
        if request.content_type == "multipart/form-data":
            mpwriter = MultipartWriter()
            await _process_multipart(await request.multipart(), mpwriter)
        else:
            data = await request.post()
        json_data = None
        if request.has_body:
            json_data = await request.json()
        if data:
            self.data.update(data)
            _LOGGER.debug("Storing data %s", data)
        elif json_data:
            self.data.update(json_data)
            _LOGGER.debug("Storing json %s", json_data)
        if request.url.path == self._proxy_url.with_path(f"{self._proxy_url.path}/stop").path:
            self.all_handler_active = False
            if self.active:
                asyncio.create_task(self.stop_proxy(3))
            return web.Response(text="Proxy stopped.")
        elif (
            request.url.path == self._proxy_url.with_path(f"{self._proxy_url.path}/resume").path
            and self.last_resp
        ):
            self.init_query = self.query.copy()
            _LOGGER.debug("Resuming request: %s", self.last_resp)
            resp = self.last_resp
        else:
            if request.url.path in [
                self._proxy_url.path,
                self._proxy_url.with_path(f"{self._proxy_url.path}/resume").path,
            ]:
                # either base path or resume without anything to resume
                site = URL(self._host_url)
                if method == "get":
                    self.init_query = self.query.copy()
                    _LOGGER.debug(
                        "Starting auth capture proxy for %s",
                        self._host_url,
                    )
            headers = await self.modify_headers(site, request)
            skip_auto_headers: List[str] = headers.get(SKIP_AUTO_HEADERS, [])
            if skip_auto_headers:
                _LOGGER.debug("Discovered skip_auto_headers %s", skip_auto_headers)
                headers.pop(SKIP_AUTO_HEADERS)
            _LOGGER.debug(
                "Attempting %s to %s\nheaders: %s \ncookies: %s",
                method,
                site,
                headers,
                self.session.cookie_jar.filter_cookies(URL(site)),
            )
            try:
                if mpwriter:
                    resp = await getattr(self.session, method)(
                        site, data=mpwriter, headers=headers, skip_auto_headers=skip_auto_headers
                    )
                elif data:
                    resp = await getattr(self.session, method)(
                        site, data=data, headers=headers, skip_auto_headers=skip_auto_headers
                    )
                elif json_data:
                    for item in ["Host", "Origin", "User-Agent", "dnt", "Accept-Encoding"]:
                        # remove proxy headers
                        if headers.get(item):
                            headers.pop(item)
                    resp = await getattr(self.session, method)(
                        site,
                        json=json_data,
                        headers=headers,
                        skip_auto_headers=skip_auto_headers,
                    )
                else:
                    resp = await getattr(self.session, method)(
                        site, headers=headers, skip_auto_headers=skip_auto_headers
                    )
            except ClientConnectionError as ex:
                return web.Response(text=f"Error connecting to {site}; please retry: {ex}")
            except TooManyRedirects as ex:
                return web.Response(text=f"Error connecting to {site}; too may redirects: {ex}")
        if resp is None:
            return web.Response(text=f"Error connecting to {site}; please retry")
        self.last_resp = resp
        print_resp(resp)
        self.check_redirects()
        self.refresh_tests()
        if self.tests:
            for test_name, test in self.tests.items():
                result = None
                result = await run_func(test, test_name, resp, self.data, self.query)
                if result:
                    _LOGGER.debug("Test %s triggered", test_name)
                    if isinstance(result, URL):
                        _LOGGER.debug(
                            "Redirecting to callback: %s",
                            result,
                        )
                        raise web.HTTPFound(location=result)
                    elif isinstance(result, str):
                        _LOGGER.debug("Displaying page:\n%s", result)
                        return web.Response(text=result, content_type="text/html")
        else:
            _LOGGER.warning("Proxy has no tests; please set.")
        content_type = resp.content_type
        self.refresh_modifiers(resp.url)
        if self.modifiers:
            modified: bool = False
            if content_type != "text/html" and content_type not in self.modifiers.keys():
                text: Text = ""
            elif content_type != "text/html" and content_type in self.modifiers.keys():
                text = await resp.text("utf-8")
            else:
                text = await resp.text()
            if text:
                for name, modifier in self.modifiers.items():
                    if isinstance(modifier, dict):
                        if name != content_type:
                            continue
                        for sub_name, sub_modifier in modifier.items():
                            try:
                                text = await run_func(sub_modifier, sub_name, text)
                                modified = True
                            except TypeError as ex:
                                _LOGGER.warning("Modifier %s is not callable: %s", sub_name, ex)
                    else:
                        # default run against text/html only
                        if content_type == "text/html":
                            try:
                                text = await run_func(modifier, name, text)
                                modified = True
                            except TypeError as ex:
                                _LOGGER.warning("Modifier %s is not callable: %s", name, ex)
                # _LOGGER.debug("Returning modified text:\n%s", text)
            if modified:
                return web.Response(
                    text=text,
                    content_type=content_type,
                )
        # pass through non parsed content
        _LOGGER.debug(
            "Passing through %s as %s",
            request.url.name if request.url.name else request.url.path,
            content_type,
        )
        return web.Response(body=await resp.read(), content_type=content_type)

    async def start_proxy(
        self, host: Optional[Text] = None, ssl_context: Optional[SSLContext] = None
    ) -> None:
        """Start proxy.

        Args:
            host (Optional[Text], optional): The host interface to bind to. Defaults to None which is "0.0.0.0" all interfaces.
            ssl_context (Optional[SSLContext], optional): SSL Context for the server. Defaults to None.
        """
        app = web.Application()
        app.add_routes(
            [
                web.route("*", "/{tail:.*}", self.all_handler),
            ]
        )
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        if not self.port:
            self._port = get_open_port()
        if self._proxy_url.scheme == "https" and ssl_context is None:
            _LOGGER.debug("Proxy url is https but no SSL Context set, downgrading to http")
            self._proxy_url = self._proxy_url.with_scheme("http")
        site = web.TCPSite(runner=self.runner, host=host, port=self.port, ssl_context=ssl_context)
        await site.start()
        self._active = True
        _LOGGER.debug("Started proxy at %s", self.access_url())

    async def stop_proxy(self, delay: int = 0) -> None:
        """Stop proxy server.

        Args:
            delay (int, optional): How many seconds to delay. Defaults to 0.
        """
        if not self.active:
            _LOGGER.debug("Proxy is not started; ignoring stop command")
            return
        _LOGGER.debug("Stopping proxy at %s after %s seconds", self.access_url(), delay)
        await asyncio.sleep(delay)
        _LOGGER.debug("Closing site runner")
        if self.runner:
            await self.runner.cleanup()
            await self.runner.shutdown()
        _LOGGER.debug("Site runner closed")
        # close session
        if self.session and not self.session.closed:
            _LOGGER.debug("Closing session")
            if self.session._connector_owner:
                if self.session._connector:
                    await self.session._connector.close()
            _LOGGER.debug("Session closed")
        self._active = False
        _LOGGER.debug("Proxy stopped")

    def _swap_proxy_and_host(self, text: Text, domain_only: bool = False) -> Text:
        """Replace host with proxy address or proxy with host address.

        Args
            text (Text): text to replace
            domain (bool): Whether only the domains should be swapped.

        Returns
            Text: Result of replacing

        """
        host_string: Text = str(self._host_url.with_path("/"))
        proxy_string: Text = str(
            self.access_url() if not domain_only else self.access_url().with_path("/")
        )
        if str(self.access_url().with_path("/")).replace("https", "http") in text:
            _LOGGER.debug(
                "Replacing %s with %s",
                str(self.access_url().with_path("/")).replace("https", "http"),
                str(self.access_url().with_path("/")),
            )
            text = text.replace(
                str(self.access_url().with_path("/")).replace("https", "http"),
                str(self.access_url().with_path("/")),
            )
        if proxy_string in text:
            if host_string[-1] == "/" and (
                not proxy_string or proxy_string == "/" or proxy_string[-1] != "/"
            ):
                proxy_string = f"{proxy_string}/"
            _LOGGER.debug("Replacing %s with %s in %s", proxy_string, host_string, text)
            return text.replace(proxy_string, host_string)
        elif host_string in text:
            if host_string[-1] == "/" and (
                not proxy_string or proxy_string == "/" or proxy_string[-1] != "/"
            ):
                proxy_string = f"{proxy_string}/"
            _LOGGER.debug("Replacing %s with %s", host_string, proxy_string)
            return text.replace(host_string, proxy_string)
        else:
            _LOGGER.debug("Unable to find %s and %s in %s", host_string, proxy_string, text)
            return text

    async def modify_headers(self, site: URL, request: web.Request) -> multidict.MultiDict:
        """Modify headers.

        Return modified headers based on site and request. To disable auto header generation,
        pass in a key const.SKIP_AUTO_HEADERS with a list of keys to not generate.

        For example, to prevent User-Agent generation: {SKIP_AUTO_HEADERS : ["User-Agent"]}

        Args:
            site (URL): URL of the next host request.
            request (web.Request): Proxy directed request. This will need to be changed for the actual host request.

        Returns:
            multidict.MultiDict: Headers after modifications
        """
        # necessary since MultiDict.update did not appear to work
        headers = multidict.MultiDict(request.headers)
        result = {}
        for k, value in headers.items():
            result[k] = value
        # _LOGGER.debug("Original headers %s", headers)
        if result.get("Host"):
            result.pop("Host")
        if result.get("Origin"):
            result["Origin"] = f"{site.with_path('')}"
        if result.get("Referer") and URL(result.get("Referer", "")).query == self.init_query:
            # Change referer for starting request; this may have query items we shouldn't pass
            result["Referer"] = str(self._host_url)
        elif result.get("Referer"):
            result["Referer"] = self._swap_proxy_and_host(
                result.get("Referer", ""), domain_only=True
            )
        for item in ["X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Scheme", "X-Real-IP"]:
            # remove proxy headers
            if result.get(item):
                result.pop(item)
        # _LOGGER.debug("Final headers %s", result)
        result.update(self.headers if self.headers else {})
        return multidict.MultiDict(result)

    def check_redirects(self) -> None:
        """Change host if redirect detected and regex does not match self.redirect_filters.

        Self.redirect_filters is a dict with key as attr in resp and value as list of regex expressions to filter against.
        """
        if not self.last_resp:
            return
        resp: ClientResponse = self.last_resp
        if resp.history:
            for item in resp.history:
                if (
                    item.status in [301, 302, 303, 304, 305, 306, 307, 308]
                    and resp.url.host != self._host_url.host
                ):
                    filtered = False
                    for attr, regex_list in self.redirect_filters.items():
                        if getattr(resp, attr) and list(
                            filter(
                                lambda regex_string: re.search(
                                    regex_string, str(getattr(resp, attr))
                                ),
                                regex_list,
                            )
                        ):
                            _LOGGER.debug(
                                "Check_redirects: Filtered out on %s in %s for resp attribute %s",
                                list(
                                    filter(
                                        lambda regex_string: re.search(
                                            regex_string, str(getattr(resp, attr))
                                        ),
                                        regex_list,
                                    )
                                ),
                                str(getattr(resp, attr)),
                                attr,
                            )
                            filtered = True
                    if filtered:
                        return
                    _LOGGER.debug(
                        "Detected %s redirect from %s to %s; changing proxy host",
                        item.status,
                        item.url.host,
                        resp.url.host,
                    )
                    self._host_url = self._host_url.with_host(str(resp.url.host))
