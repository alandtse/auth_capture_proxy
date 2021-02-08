#  SPDX-License-Identifier: Apache-2.0
"""Python Package for auth capture proxy."""
import logging
from typing import Any, Callable, Dict, Optional, Text

import asyncio
from aiohttp import web, ClientSession, ClientConnectionError, TooManyRedirects
from aiohttp.client_reqrep import ClientResponse
import multidict
from ssl import SSLContext
from yarl import URL

from authcaptureproxy.helper import print_resp
from authcaptureproxy.stackoverflow import get_open_port

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
        self._active = False
        self._all_handler_active = True

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
        self._tests = value

    @property
    def modifiers(self) -> Dict[Text, Callable]:
        """Return modifiers setting.

        :setter: value (Dict[Text, Any]): A dictionary of modifiers. The key should be the name of the modifier and the value should be a function or couroutine that takes a string and returns a modified string. If parameters are necessary, functools.partial should be used. See :mod:`authcaptureproxy.examples.modifiers` for examples.
        """
        return self._modifiers

    @modifiers.setter
    def modifiers(self, value: Dict[Text, Callable]) -> None:
        """Set tests.

        Args:
            value (Dict[Text, Any]): A dictionary of tests.
        """
        self._modifiers = value

    async def change_host_url(self, new_url: URL) -> None:
        """Change the host url of the proxy.

        This will also reset all stored data.

        Args:
            new_url (URL): original url for login, e.g., http://amazon.com
        """
        if not isinstance(new_url, URL):
            raise ValueError("URL required")
        self._host_url = new_url
        await self.reset_data

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

    def access_url(self) -> URL:
        """Return access url for proxy with port."""
        return self._proxy_url.with_port(self.port)

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
        if not self.all_handler_active:
            _LOGGER.debug("%s all_handler is disabled; returning 404.", self)
            raise web.HTTPNotFound()
        if not self.session:
            self.session = ClientSession()
        method = request.method.lower()
        resp: Optional[ClientResponse] = None
        site = URL(self._swap_proxy_and_host(str(request.url)))
        _LOGGER.debug("%s: %s", method, request.url)
        self.query.update(request.query)
        data = await request.post()
        if data:
            self.data.update(await request.post())
        if request.url.path == self._proxy_url.with_path(f"{self._proxy_url.path}/stop").path:
            self.all_handler_active = False
            if self.active:
                asyncio.create_task(self.stop_proxy(3))
            return web.Response(text=f"Proxy stopped.")
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
                site: URL = self._host_url
                self.init_query = self.query.copy()
                _LOGGER.debug(
                    "Starting auth capture proxy for %s",
                    self._host_url,
                )
            headers = self._change_headers(site, request)
            _LOGGER.debug("Attempting %s to %s", method, site)
            try:
                if data:
                    resp = await getattr(self.session, method)(site, data=data, headers=headers)
                else:
                    resp = await getattr(self.session, method)(site, headers=headers)
            except ClientConnectionError as ex:
                return web.Response(text=f"Error connecting to {site}; please retry: {ex}")
            except TooManyRedirects as ex:
                return web.Response(text=f"Error connecting to {site}; too may redirects: {ex}")
        if resp is None:
            return web.Response(text=f"Error connecting to {site}; please retry")
        self.last_resp = resp
        print_resp(resp)
        if self.tests:
            for test_name, test in self.tests.items():
                result = None
                if asyncio.iscoroutinefunction(test):
                    _LOGGER.debug("Running coroutine test %s", test_name)
                    result = await test(resp, self.data, self.query)
                else:
                    _LOGGER.debug("Running function test %s", test_name)
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
        content_type = resp.content_type
        if content_type == "text/html":
            text = self._swap_proxy_and_host(await resp.text())
            if self.modifiers:
                for name, modifier in self.modifiers.items():
                    if asyncio.iscoroutinefunction(modifier):
                        _LOGGER.debug("Applied coroutine modifier: %s", name)
                        text = await modifier(text)
                    else:
                        _LOGGER.debug("Applied function modifier: %s", name)
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
        await self.runner.cleanup()
        await self.runner.shutdown()

    def _swap_proxy_and_host(self, text: Text, domain_only: bool = False) -> Text:
        """Replace host with proxy address or proxy with host address

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
        if not proxy_string or proxy_string == "/" or proxy_string[-1] != "/":
            proxy_string = f"{proxy_string}/"
        if proxy_string in text:
            _LOGGER.debug("Replacing %s with %s", proxy_string, host_string)
            return text.replace(proxy_string, host_string)
        elif proxy_string.replace("https", "http") in text:
            _LOGGER.debug(
                "Replacing %s with %s", proxy_string.replace("https", "http"), host_string
            )
            return text.replace(proxy_string.replace("https", "http"), host_string)
        elif host_string in text:
            _LOGGER.debug("Replacing %s with %s", host_string, proxy_string)
            return text.replace(host_string, proxy_string)
        else:
            _LOGGER.debug("Unable to find %s and %s in %s", host_string, proxy_string, text)
            return text

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
            result["Referer"] = self._swap_proxy_and_host(result.get("Referer"), domain_only=True)
        # _LOGGER.debug("Final headers %s", result)
        return result
