#  SPDX-License-Identifier: Apache-2.0
"""Python Package for auth capture proxy."""
import logging
from typing import Any, Callable, Dict, Optional, Text

import asyncio
from aiohttp import web, ClientSession, ClientConnectionError
from aiohttp.client_reqrep import ClientResponse
import multidict
from ssl import SSLContext
from yarl import URL

from .helper import print_resp
from .stackoverflow import get_open_port

_LOGGER = logging.getLogger(__name__)


class AuthCaptureProxy:
    """Class to handle proxy login connections.

    This class relies on tests to be provided to indicate the proxy has completed. At proxy completion all data can be found in self.session, self.data, and self.query."""

    def __init__(
        self, proxy_url: URL, host_url: URL, session: Optional[ClientSession] = None
    ) -> None:
        """Initialize proxy object.

        Args:
            proxy_url (URL): url for proxy location. e.g., http://192.168.1.1/. If there is any path, the path is considered part of the base url. If no explicit port is specified, a random port will be generated. If https is passed in, ssl_context must be provided at start_proxy() or the url will be downgraded to http.
            host_url (URL): original url for login, e.g., http://amazon.com
            session (ClientSession): Session to make aiohttp queries. Optional

        """
        self.session: ClientSession = session if session else ClientSession()
        self._proxy_url: URL = proxy_url
        self._host_url: URL = host_url
        self._port: int = proxy_url.explicit_port if proxy_url.explicit_port else 0
        self.runner: web.AppRunner = None
        self.last_resp: Optional[ClientResponse] = None
        self.init_query: Dict[Text, Any] = {}
        self.query: Dict[Text, Any] = {}
        self.data: Dict[Text, Any] = {}
        self._tests: Dict[Text, Callable] = {}
        self._modifiers: Dict[Text, Callable] = {}

    @property
    def port(self) -> int:
        """Return port setting."""
        return self._port

    @property
    def tests(self) -> Dict[Text, Callable]:
        """Return tests setting.

        :setter: value (Dict[Text, Any]): A dictionary of tests. The key should be the name of the test and the value should be a synchronous function that takes a ClientResponse, a dictionary of post variables, and a dictioary of query variables and returns a URL or string. See :mod:`authcaptureproxy.examples.testers` for examples.
        """
        return self._tests

    @tests.setter
    def tests(self, value: Dict[Text, Callable]) -> None:
        """Set tests.

        Args:
            value (Dict[Text, Any]): A dictionary of tests.
        """
        self._tests = value

    @property
    def modifiers(self) -> Dict[Text, Callable]:
        """Return modifiers setting.

        :setter: value (Dict[Text, Any]): A dictionary of modifiers. The key should be the name of the modifier and the value should be a synchronous function that takes a string and returns a modified string. If parameters are necessary, functools.partial should be used. See :mod:`authcaptureproxy.examples.modifiers` for examples.
        """
        return self._modifiers

    @modifiers.setter
    def modifiers(self, value: Dict[Text, Callable]) -> None:
        """Set tests.

        Args:
            value (Dict[Text, Any]): A dictionary of tests.
        """
        self._modifiers = value

    def access_url(self) -> URL:
        """Return access url for proxy with port."""
        return self._proxy_url.with_port(self.port)

    async def all_handler(self, request: web.Request) -> web.Response:
        """Handle all requests.

        This handler will exit on succesful test found in self.tests or if a /stop url is seen. This handler can be used with any aiohttp webserver.

        Args
            request (web.Request): The request to process

        Returns
            web.Response: The webresponse to the browser

        Raises
            web.HTTPFound: Redirect URL upon success

        """

        method = request.method.lower()
        resp: Optional[ClientResponse] = None
        site = URL(self._change_proxy_to_host(str(request.url)))
        _LOGGER.debug("%s: %s", method, request.url)
        self.query.update(request.query)
        data = await request.post()
        if data:
            self.data.update(await request.post())
        if request.url.path == f"{self._proxy_url.path}stop":
            asyncio.create_task(self.stop_proxy(3))
            return web.Response(text=f"Proxy stopped.")
        elif request.url.path == f"{self._proxy_url.path}resume" and self.last_resp:
            self.init_query = self.query.copy()
            _LOGGER.debug("Resuming request: %s", self.last_resp)
            resp = self.last_resp
        else:
            if request.url.path in [self._proxy_url.path, f"{self._proxy_url.path}resume"]:
                # either base path or resume without anything to resume
                site: URL = self._host_url
                self.init_query = self.query.copy()
                _LOGGER.debug(
                    "Starting auth capture proxy for %s",
                    self._host_url,
                )
            headers = self._change_headers(site, request)
            try:
                if data:
                    resp = await getattr(self.session, method)(site, data=data, headers=headers)
                else:
                    resp = await getattr(self.session, method)(site, headers=headers)
            except ClientConnectionError as ex:
                return web.Response(text=f"Error connecting to {site}; please retry: {ex}")
        if resp is None:
            return web.Response(text=f"Error connecting to {site}; please retry")
        self.last_resp = resp
        print_resp(resp)
        if self.tests:
            for test_name, test in self.tests.items():
                result = test(resp, self.data, self.query)
                if result:
                    _LOGGER.debug("Test %s reports success", test_name)
                    if isinstance(result, URL):
                        _LOGGER.debug(
                            "Redirecting to callback: %s",
                            result,
                        )
                        raise web.HTTPFound(location=result)
                    elif isinstance(result, str):
                        _LOGGER.debug("Displaying success page: %s", result)
                        return web.Response(
                            text=result,
                        )
        else:
            _LOGGER.warning("Proxy has no tests; please set.")
        print_resp(resp)
        content_type = resp.content_type
        if content_type == "text/html":
            text = self._change_host_to_proxy(await resp.text())
            if self.modifiers:
                for name, modifier in self.modifiers.items():
                    _LOGGER.debug("Applied modifier: %s", name)
                    text = modifier(text)
            return web.Response(
                text=text,
                content_type=content_type,
            )
        # handle non html content
        return web.Response(body=await resp.content.read(), content_type=content_type)

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
        _LOGGER.debug("Started proxy at %s", self.access_url())

    async def stop_proxy(self, delay: int = 0) -> None:
        """Stop proxy server.

        Args:
            delay (int, optional): How many seconds to delay. Defaults to 0.
        """
        _LOGGER.debug("Stopping proxy at %s after %s seconds", self.access_url(), delay)
        await asyncio.sleep(delay)
        await self.runner.cleanup()
        await self.runner.shutdown()

    def _change_proxy_to_host(self, text: Text) -> Text:
        """Replace text with proxy address.

        Args
            text (Text): text to replace

        Returns
            Text: Result of replacing

        """
        return text.replace(
            str(self.access_url().with_path("/")), str(self._host_url.with_path("/"))
        )

    def _change_host_to_proxy(self, text: Text) -> Text:
        """Replace text with host address.

        Args
            text (Text): text to replace

        Returns
            Text: Result of replacing

        """
        return text.replace(
            str(self._host_url.with_path("/")), str(self.access_url().with_path("/"))
        )

    def _change_headers(self, site: URL, request: web.Request) -> multidict.MultiDict:
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
        if result.get("Referer") and URL(result.get("Referer")).query == self.init_query:
            # Remove referer for starting request; this may have query items we shouldn't pass
            result.pop("Referer")
        elif result.get("Referer"):
            result["Referer"] = self._change_proxy_to_host(result.get("Referer"))
        # _LOGGER.debug("Final headers %s", result)
        return result
