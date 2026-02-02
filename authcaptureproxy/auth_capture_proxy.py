#  SPDX-License-Identifier: Apache-2.0
"""Python Package for auth capture proxy."""
import asyncio
import logging
import re
from json import JSONDecodeError
from functools import partial
from ssl import SSLContext, create_default_context
from typing import Any, Callable, Dict, List, Optional, Set, Text, Tuple, Union

import httpx
from aiohttp import (
    MultipartReader,
    MultipartWriter,
    hdrs,
    web,
)
from multidict import CIMultiDict
from yarl import URL

from authcaptureproxy.const import SKIP_AUTO_HEADERS
from authcaptureproxy.examples.modifiers import (
    prepend_relative_urls,
    replace_empty_action_urls,
    replace_matching_urls,
)
from authcaptureproxy.helper import (
    convert_multidict_to_dict,
    get_content_type,
    get_nested_dict_keys,
    print_resp,
    run_func,
    swap_url,
)
from authcaptureproxy.stackoverflow import get_open_port

# Pre-configure SSL context
ssl_context = create_default_context()

_LOGGER = logging.getLogger(__name__)


class AuthCaptureProxy:
    """Class to handle proxy login connections.

    This class relies on tests to be provided to indicate the proxy has completed. At proxy completion all data can be found in self.session, self.data, and self.query.
    """

    def __init__(self,
        proxy_url: URL,
        host_url: URL,
        session: Optional[httpx.AsyncClient] = None,
        session_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
        preserve_headers: bool = False,
    ) -> None:
        """Initialize proxy object.

        Args:
            proxy_url (URL): url for proxy location. e.g., http://192.168.1.1/.
                If there is any path, the path is considered part of the base url.
                If no explicit port is specified, a random port will be generated.
                If https is passed in, ssl_context must be provided at start_proxy() or the url will be downgraded to http.
            host_url (URL): original url for login, e.g., http://amazon.com
            session (httpx.AsyncClient): httpx client to make queries. Optional
            session_factory (lambda: httpx.AsyncClient): factory to create the aforementioned httpx client if having one fixed session is insufficient.
            preserve_headers (bool): Whether to preserve headers from the backend. Useful in circumventing CSRF protection. Defaults to False.
        """
        self._preserve_headers = preserve_headers
        self.session_factory: Callable[[], httpx.AsyncClient] = session_factory or (
            lambda: httpx.AsyncClient(verify=ssl_context)
        )
        self.session: httpx.AsyncClient = session if session else self.session_factory()
        self._proxy_url: URL = proxy_url
        self._host_url: URL = host_url
        self._port: int = proxy_url.explicit_port if proxy_url.explicit_port else 0  # type: ignore
        self.runner: Optional[web.AppRunner] = None
        self.last_resp: Optional[httpx.Response] = None
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
        self._background_tasks: Set[asyncio.Task] = set()

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

        :setter: value (Dict[Text, Any]): A dictionary of tests. The key should be the name of the test and the value should be a function or coroutine that takes a httpx.Response, a dictionary of post variables, and a dictioary of query variables and returns a URL or string. See :mod:`authcaptureproxy.examples.testers` for examples.
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

        :setter: value (Dict[Text, Dict[Text, Callable]): A nested dictionary of modifiers. The key should be a MIME type and the value should be a dictionary of modifiers for that MIME type where the key should be the name of the modifier and the value should be a function or coroutine that takes a string and returns a modified string. If parameters are necessary, functools.partial should be used. See :mod:`authcaptureproxy.examples.modifiers` for examples.
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
        return self._proxy_url.with_port(self.port) if self.port != 0 else self._proxy_url

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
        if self.session:
            await self.session.aclose()
        self.session = self.session_factory()
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
        DEFAULT_MODIFIERS = {  # noqa: N806
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

    @staticmethod
    def _filter_ajax_headers(resp: httpx.Response) -> dict:
        """Filter headers for AJAX responses, removing hop-by-hop and CSP headers."""
        _skip_headers = {
            "content-type", "content-length", "content-encoding",
            "transfer-encoding", "connection",
            "x-connection-hash", "set-cookie",
            "content-security-policy",
            "content-security-policy-report-only",
        }
        filtered = {}
        for k, v in resp.headers.items():
            if k.lower() not in _skip_headers:
                filtered[k] = v
        filtered["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return filtered

    async def _build_response(
        self, response: Optional[httpx.Response] = None, *args, **kwargs
    ) -> web.Response:
        """
        Build a response.
        """
        if "headers" not in kwargs and response is not None:
            kwargs["headers"] = response.headers.copy() if self._preserve_headers else CIMultiDict()

            if hdrs.CONTENT_TYPE in kwargs["headers"] and "content_type" in kwargs:
                del kwargs["headers"][hdrs.CONTENT_TYPE]

            if hdrs.CONTENT_LENGTH in kwargs["headers"]:
                del kwargs["headers"][hdrs.CONTENT_LENGTH]

            if hdrs.CONTENT_ENCODING in kwargs["headers"]:
                del kwargs["headers"][hdrs.CONTENT_ENCODING]

            if hdrs.CONTENT_TRANSFER_ENCODING in kwargs["headers"]:
                del kwargs["headers"][hdrs.CONTENT_TRANSFER_ENCODING]

            if hdrs.TRANSFER_ENCODING in kwargs["headers"]:
                del kwargs["headers"][hdrs.TRANSFER_ENCODING]

            if "x-connection-hash" in kwargs["headers"]:
                del kwargs["headers"]["x-connection-hash"]

            while hdrs.SET_COOKIE in kwargs["headers"]:
                del kwargs["headers"][hdrs.SET_COOKIE]

            # cache control

            if hdrs.CACHE_CONTROL in kwargs["headers"]:
                del kwargs["headers"][hdrs.CACHE_CONTROL]

            kwargs["headers"][hdrs.CACHE_CONTROL] = "no-cache, no-store, must-revalidate"

        return web.Response(*args, **kwargs)

    async def all_handler(self, request: web.Request, **kwargs) -> web.Response:
        """Handle all requests.

        This handler will exit on successful test found in self.tests or if a /stop url is seen. This handler can be used with any aiohttp webserver and disabled after registered using self.all_haandler_active.

        Args
            request (web.Request): The request to process
            **kwargs: Additional keyword arguments
                access_url (URL): The access url for the proxy. Defaults to self.access_url()
                host_url (URL): The host url for the proxy. Defaults to self._host_url

        Returns
            web.Response: The webresponse to the browser

        Raises
            web.HTTPFound: Redirect URL upon success
            web.HTTPNotFound: Return 404 when all_handler is disabled

        """
        if "access_url" in kwargs:
            access_url = kwargs.pop("access_url")
        else:
            access_url = self.access_url()

        if "host_url" in kwargs:
            host_url = kwargs.pop("host_url")
        else:
            host_url = self._host_url

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
                elif hdrs.CONTENT_TYPE in part.headers:
                    content_type = part.headers.get(hdrs.CONTENT_TYPE, "")
                    mime_type = content_type.split(";", 1)[0].strip()
                    if mime_type == "application/json":
                        try:
                            part_data: Optional[
                                Union[Text, Dict[Text, Any], List[Tuple[Text, Text]], bytes]
                            ] = await part.json()
                            writer.append_json(part_data)
                        except (JSONDecodeError, ValueError, TypeError):
                            # Best-effort fallback: text, then bytes
                            try:
                                part_text = await part.text()
                                writer.append(part_text)
                            except (UnicodeDecodeError, ValueError):
                                part_data = await part.read()
                                writer.append(part_data)
                    elif mime_type.startswith("text"):
                        part_data = await part.text()
                        writer.append(part_data)
                    elif mime_type == "application/x-www-form-urlencoded":
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
        # if not self.session:
        #     self.session = httpx.AsyncClient()
        method = request.method.lower()
        _LOGGER.debug("Received %s: %s for %s", method, str(request.url), host_url)
        resp: Optional[httpx.Response] = None
        # Multi-host AJAX routing: handle requests to non-default Amazon
        # subdomains that the injected JavaScript redirected through the proxy.
        # Path format: .../proxy/__amzn_host__fls-eu.amazon.com/1/batch/...
        _amzn_host_marker = "/__amzn_host__"
        _req_path = URL(str(request.url)).path
        if _amzn_host_marker in _req_path:
            _marker_pos = _req_path.index(_amzn_host_marker) + len(_amzn_host_marker)
            _remaining = _req_path[_marker_pos:]
            _slash_pos = _remaining.find("/")
            if _slash_pos > 0:
                _alt_host = _remaining[:_slash_pos]
                _alt_path = _remaining[_slash_pos:]
            else:
                _alt_host = _remaining
                _alt_path = "/"
            if not _alt_host:
                _LOGGER.warning(
                    "Malformed __amzn_host__ path: no host in %s", _req_path,
                )
                return await self._build_response(
                    text="Invalid multi-host AJAX path",
                )
            _allowed_host_patterns = (
                r'\.(amazon\.(com|it|co\.uk|de|fr|es|co\.jp|ca|com\.au|in|com\.br)'
                r'|awswaf\.com|amazoncognito\.com|ssl-images-amazon\.com)$'
            )
            if not re.search(_allowed_host_patterns, _alt_host):
                _LOGGER.warning(
                    "Blocked request to non-Amazon host via __amzn_host__: %s",
                    _alt_host,
                )
                return await self._build_response(
                    text="Host not allowed",
                )
            site = f"https://{_alt_host}{_alt_path}"
            if request.query_string:
                site += f"?{request.query_string}"
            _LOGGER.debug(
                "Multi-host AJAX proxy: %s -> %s", _req_path, site,
            )
        else:
            old_url: URL = (
                access_url.with_host(request.url.host)
                if request.url.host and request.url.host != access_url.host
                else access_url
            )
            if request.scheme == "http" and access_url.scheme == "https":
                # detect reverse proxy downgrade
                _LOGGER.debug("Detected http while should be https; switching to https")
                site: str = str(
                    swap_url(
                        ignore_query=True,
                        old_url=old_url.with_scheme("https"),
                        new_url=host_url.with_path("/"),
                        url=URL(str(request.url)).with_scheme("https"),
                    ),
                )
            else:
                site = str(
                    swap_url(
                        ignore_query=True,
                        old_url=old_url,
                        new_url=host_url.with_path("/"),
                        url=URL(str(request.url)),
                    ),
                )
        self.query.update(request.query)
        data: Optional[Dict] = None
        raw_body: Optional[bytes] = None
        mpwriter = None
        if request.content_type == "multipart/form-data":
            mpwriter = MultipartWriter()
            await _process_multipart(await request.multipart(), mpwriter)
        elif (
            request.has_body
            and request.content_type
            and "x-www-form-urlencoded" not in request.content_type
            and "json" not in request.content_type
        ):
            # Raw body (text/plain, binary, etc.) - forward as-is.
            raw_body = await request.read()
            _LOGGER.debug(
                "Read raw body (%s bytes, type=%s) for %s",
                len(raw_body) if raw_body else 0,
                request.content_type,
                site,
            )
        else:
            data = convert_multidict_to_dict(await request.post())
        json_data = None
        # Only attempt JSON decoding for JSON requests; avoid raising for form posts.
        if request.has_body and (
            request.content_type == "application/json"
            or request.content_type.endswith("+json")
        ):
            try:
                json_data = await request.json()
            except (JSONDecodeError, ValueError):
                json_data = None
        if data:
            self.data.update(data)
            _LOGGER.debug("Storing data %s", data)
            # Previously appended TOTP to password for signin to bypass
            # CVF. No longer needed: the aamation captcha challenge now
            # handles CVF verification. Appending TOTP to the password
            # causes Amazon to reject the password as incorrect.
            if (
                data.get("password")
                and hasattr(self, '_login')
                and self._login is not None
                and "/ap/signin" in site
            ):
                _LOGGER.debug(
                    "Signin POST: password present (not appending TOTP), "
                    "site: %s",
                    site,
                )
            # Fix CVF verify POST from browser.
            # The browser's JS fails the aamation challenge with NetworkError
            # (AJAX can't reach Amazon's servers through the proxy) and sets
            # a fake "staticSessionToken". We ALWAYS strip the failed aamation
            # data so Amazon doesn't see the JS error. OTP is injected only
            # when a TOTP key is configured.
            if (
                hasattr(self, '_login')
                and self._login is not None
                and "/ap/cvf/verify" in site
            ):
                _aam_token = data.get("cvf_aamation_response_token", "")
                _LOGGER.debug(
                    "CVF verify POST: aamation_token='%.40s', "
                    "error_code='%s', captcha_action='%s', "
                    "clientSideContext=%s",
                    _aam_token,
                    data.get("cvf_aamation_error_code", ""),
                    data.get("cvf_captcha_captcha_action", ""),
                    "present" if data.get("clientSideContext") else "absent",
                )
                # If aamation token looks valid (base64 JSON), keep it
                if _aam_token and _aam_token.startswith("eyJ"):
                    _LOGGER.debug(
                        "CVF verify: valid aamation token detected, "
                        "forwarding as-is with %d fields",
                        len(data),
                    )
                else:
                    # Aamation challenge failed - clear and inject OTP
                    data["cvf_aamation_response_token"] = ""
                    data["cvf_aamation_error_code"] = ""
                    data["cvf_captcha_captcha_action"] = ""
                    _get_totp = getattr(self._login, "get_totp_token", None)
                    _totp_for_cvf = _get_totp() if callable(_get_totp) else None
                    if _totp_for_cvf:
                        data["otpCode"] = _totp_for_cvf
                        data["rememberDevice"] = "true"
                    _LOGGER.debug(
                        "CVF verify: no valid aamation, cleared fields, "
                        "OTP=%s",
                        "injected" if _totp_for_cvf else "not available",
                    )
        elif json_data:
            self.data.update(json_data)
            _LOGGER.debug("Storing json %s", json_data)
        if URL(str(request.url)).path == re.sub(
            r"/+", "/", self._proxy_url.with_path(f"{self._proxy_url.path}/stop").path
        ):
            self.all_handler_active = False
            if self.active:
                task = asyncio.create_task(self.stop_proxy(3))
                self._background_tasks.add(task)
                task.add_done_callback(self._background_tasks.discard)
            return await self._build_response(text="Proxy stopped.")
        elif (
            URL(str(request.url)).path
            == re.sub(r"/+", "/", self._proxy_url.with_path(f"{self._proxy_url.path}/resume").path)
            and self.last_resp
            and isinstance(self.last_resp, httpx.Response)
        ):
            self.init_query = self.query.copy()
            _LOGGER.debug("Resuming request: %s", self.last_resp)
            resp = self.last_resp
        else:
            if URL(str(request.url)).path in [
                self._proxy_url.path,
                re.sub(
                    r"/+", "/", self._proxy_url.with_path(f"{self._proxy_url.path}/resume").path
                ),
            ]:
                # either base path or resume without anything to resume
                site = str(URL(host_url))
                if method == "get":
                    self.init_query = self.query.copy()
                    _LOGGER.debug(
                        "Starting auth capture proxy for %s",
                        host_url,
                    )
            headers = await self.modify_headers(URL(site), request)
            skip_auto_headers: List[str] = headers.get(SKIP_AUTO_HEADERS, [])
            if skip_auto_headers:
                _LOGGER.debug("Discovered skip_auto_headers %s", skip_auto_headers)
                headers.pop(SKIP_AUTO_HEADERS)
            # Avoid accidental header mutation across branches/calls
            req_headers: dict[str, Any] = dict(headers)
            _LOGGER.debug(
                "Attempting %s to %s\nheaders: %s \ncookies: %s",
                method,
                site,
                req_headers,
                self.session.cookies.jar,
            )
            try:
                if mpwriter:
                    resp = await getattr(self.session, method)(
                        site, data=mpwriter, headers=req_headers, follow_redirects=True
                    )
                elif data:
                    resp = await getattr(self.session, method)(
                        site, data=data, headers=req_headers, follow_redirects=True
                    )
                elif raw_body is not None:
                    _LOGGER.debug(
                        "Sending raw body (%s bytes, Content-Type: %s) to %s",
                        len(raw_body),
                        request.content_type,
                        site,
                    )
                    # Preserve the original Content-Type for raw body requests
                    if request.content_type and "Content-Type" not in req_headers:
                        req_headers["Content-Type"] = request.content_type
                    resp = await getattr(self.session, method)(
                        site, content=raw_body, headers=req_headers, follow_redirects=True
                    )
                elif json_data:
                    for item in ["Host", "Origin", "User-Agent", "dnt", "Accept-Encoding"]:
                        # remove proxy headers
                        if req_headers.get(item):
                            req_headers.pop(item)
                    resp = await getattr(self.session, method)(
                        site, json=json_data, headers=req_headers, follow_redirects=True
                    )
                else:
                    resp = await getattr(self.session, method)(
                        site, headers=req_headers, follow_redirects=True
                    )
            except httpx.ConnectError as ex:
                return await self._build_response(
                    text=f"Error connecting to {site}; please retry: {ex}"
                )
            except httpx.TooManyRedirects as ex:
                return await self._build_response(
                    text=f"Error connecting to {site}; too many redirects: {ex}"
                )
            except httpx.TimeoutException as ex:
                _LOGGER.warning(
                    "Timeout connecting to %s: %s", site, ex
                )
                return await self._build_response(
                    text=(
                        f"Timeout connecting to {site}: {ex}. "
                        "Please try again. If this persists, check your network "
                        "and that the service endpoint is reachable from this host."
                    )
                )
            except httpx.HTTPError as ex:
                return await self._build_response(
                    text=f"Error connecting to {site}: {ex}"
                )
        if resp is None:
            return await self._build_response(text=f"Error connecting to {site}; please retry")
        self.last_resp = resp
        print_resp(resp)
        # CVF page detection - log only, let browser handle the page.
        # The browser's JavaScript must complete the aamation challenge to fill
        # cvf_aamation_response_token. When the browser submits the form,
        # the proxy injects otpCode into the POST data (see above).
        if (
            resp is not None
            and resp.status_code == 200
            and hasattr(self, '_login')
            and self._login is not None
            and "/ap/cvf/" in URL(str(resp.url)).path
        ):
            _LOGGER.debug(
                "CVF page detected at %s - browser aamation challenge",
                resp.url,
            )
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
                        return await self._build_response(
                            resp, text=result, content_type="text/html"
                        )
        else:
            _LOGGER.warning("Proxy has no tests; please set.")
        content_type = get_content_type(resp)
        # Detect AJAX requests: browser navigation includes
        # "Upgrade-Insecure-Requests: 1" while XHR/fetch does not.
        # AJAX HTML responses must NOT be processed by modifiers
        # (URL rewriting, autofill) because that corrupts the content
        # expected by the calling JavaScript (e.g., aamation challenge).
        _is_ajax = request.headers.get("Upgrade-Insecure-Requests") != "1"
        if _is_ajax:
            _LOGGER.debug(
                "AJAX response for %s: status=%s, content_type=%s",
                URL(str(request.url)).path,
                resp.status_code,
                content_type,
            )
        if _is_ajax and content_type == "text/html":
            _ajax_body = resp.content
            # Inject P shim + mini jQuery into aaut/verify/cvf response
            # so that Amazon's A-framework dependency P.when('A','ready')
            # resolves and CaptchaScript.renderCaptcha() can execute.
            if "/aaut/verify/cvf" in URL(str(request.url)).path and _ajax_body:
                try:
                    _decoded = _ajax_body.decode("utf-8", errors="replace")
                    # Extract the awswaf.com hostname from the script src
                    _awswaf_match = re.search(
                        r'src=["\']https?://([a-z0-9.\-]+\.awswaf\.com)',
                        _decoded, re.IGNORECASE,
                    )
                    _awswaf_host = _awswaf_match.group(1) if _awswaf_match else ""
                    _LOGGER.debug(
                        "Extracted awswaf host from aaut HTML: %s",
                        _awswaf_host or "(not found)",
                    )
                    # Extract the real Amazon domain from self._host_url
                    # so captcha.js sends the correct domain to WAF (not 192.168.x.x)
                    _amazon_domain = str(self._host_url.host) if self._host_url else ""
                    _LOGGER.debug(
                        "Amazon domain for WAF captcha: %s",
                        _amazon_domain or "(not found)",
                    )
                    # Sanitize hostnames before interpolating into JavaScript
                    _safe_host_re = re.compile(r'^[a-z0-9.\-]+$', re.IGNORECASE)
                    if _awswaf_host and not _safe_host_re.match(_awswaf_host):
                        _LOGGER.warning("Skipping invalid awswaf host: %s", _awswaf_host)
                        _awswaf_host = ""
                    if _amazon_domain and not _safe_host_re.match(_amazon_domain):
                        _LOGGER.warning("Skipping invalid amazon domain: %s", _amazon_domain)
                        _amazon_domain = ""
                    # AJAX proxy wrapper for the aaut iframe context.
                    # captcha.js uses relative URLs (e.g., /ait/ait/ait/verify)
                    # which need to be routed through the proxy to awswaf.com.
                    _aaut_ajax_proxy = (
                        '<script>'
                        '(function(){'
                        'var pp=window.location.pathname.split("/aaut/")[0];'
                        'if(!pp||pp===window.location.pathname)pp=window.location.pathname.split("/ap/")[0];'
                        'var wafHost="' + _awswaf_host + '";'
                        'var amazonDomain="' + _amazon_domain + '";'
                        'function rw(u){'
                        'try{var p=new URL(u,window.location.href);'
                        'if(p.hostname.match(/\\.awswaf\\.com$/)){'
                        'return pp+"/__amzn_host__"+p.hostname+p.pathname+p.search;}'
                        'if(wafHost&&p.hostname===window.location.hostname'
                        '&&p.pathname.indexOf("/ait/")===0){'
                        'return pp+"/__amzn_host__"+wafHost+p.pathname+p.search;}'
                        'if(p.hostname.match(/\\.(amazon\\.(com|it|co\\.uk|de|fr|es|co\\.jp|ca|com\\.au|in|com\\.br)|amazoncognito\\.com)$/)){'
                        'if(p.hostname==="www.amazon.com"||p.hostname===window.location.hostname)'
                        'return pp+p.pathname+p.search;'
                        'return pp+"/__amzn_host__"+p.hostname+p.pathname+p.search;}'
                        '}catch(e){}return u;}'
                        'var xo=XMLHttpRequest.prototype.open;'
                        'XMLHttpRequest.prototype.open=function(m,u){'
                        'if(typeof u==="string"){this.__origUrl=u;arguments[1]=rw(u);}'
                        'return xo.apply(this,arguments);};'
                        'var _xrd=Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype,"responseURL");'
                        'if(_xrd&&_xrd.get){Object.defineProperty(XMLHttpRequest.prototype,"responseURL",{'
                        'get:function(){return this.__origUrl||_xrd.get.call(this);},configurable:true});}'
                        # Wrap fetch with domain rewriting.
                        # The /problem request sends domain=window.location.hostname
                        # (e.g., 192.168.1.103) which WAF rejects. Rewrite to the
                        # real Amazon domain so WAF validates correctly.
                        'var fo=window.fetch;'
                        'if(fo)window.fetch=function(i,n){'
                        'var orig=typeof i==="string"?i:i;'
                        'if(amazonDomain&&typeof i==="string"&&i.indexOf("/problem")!==-1){'
                        'i=i.replace(/domain=[^&]+/,"domain="+encodeURIComponent(amazonDomain));}'
                        'if(typeof i==="string")i=rw(i);'
                        'return fo.call(this,i,n).then(function(r){'
                        'if(i!==orig)Object.defineProperty(r,"url",{value:orig,configurable:true});'
                        'return r;'
                        '});};'
                        '})();'
                        '</script>'
                    )
                    _p_shim = (
                        '<script>'
                        '(function(){'
                        # Mini jQuery shim providing $(), .click(), .length
                        'function mQ(s){'
                        'var els=document.querySelectorAll(s);'
                        'var r=Array.prototype.slice.call(els);'
                        'r.click=function(fn){r.forEach(function(e){e.addEventListener("click",fn)});return r;};'
                        'return r;}'
                        # P.when(...).execute(fn) shim - waits for CaptchaScript
                        'window.P=window.P||{when:function(){'
                        'return{execute:function(fn){'
                        'function go(){'
                        'if(typeof CaptchaScript!=="undefined"){'
                        'try{fn({$:mQ});}catch(e){console.error("[AMP] P shim execute error:",e);}'
                        '}else{setTimeout(go,100);}}'
                        'if(document.readyState==="loading"){'
                        'document.addEventListener("DOMContentLoaded",go);'
                        '}else{go();}'
                        '}};'
                        '}};'
                        '})();'
                        '</script>'
                    )
                    # Inject shim right before the first <script> in <head>
                    _head_end = _decoded.lower().find('</head>')
                    if _head_end < 0:
                        _head_end = _decoded.lower().find('<body')
                    _first_script = _decoded.lower().find('<script', 1)
                    if _first_script > 0:
                        _inject_pos = _first_script
                    elif _head_end > 0:
                        _inject_pos = _head_end
                    else:
                        _inject_pos = 0
                    _decoded = _decoded[:_inject_pos] + _aaut_ajax_proxy + _p_shim + _decoded[_inject_pos:]
                    # Rewrite captcha.js <script src> to load through the proxy.
                    # captcha.js determines its base URL by scanning <script> tags
                    # for src ending with /captcha.js. By proxying the script,
                    # p() returns a proxy URL, so /problem and /verify API calls
                    # naturally route through the proxy (the URL path already
                    # contains __amzn_host__).
                    if _awswaf_host:
                        _proxy_prefix = URL(str(request.url)).path.split("/aaut/")[0]
                        if not _proxy_prefix or _proxy_prefix == URL(str(request.url)).path:
                            _proxy_prefix = URL(str(request.url)).path.split("/ap/")[0]
                        _old_waf_base = f"https://{_awswaf_host}/"
                        _new_waf_base = f"{_proxy_prefix}/__amzn_host__{_awswaf_host}/"
                        _decoded = _decoded.replace(_old_waf_base, _new_waf_base)
                        _LOGGER.debug(
                            "Rewrote awswaf script src to proxy: %s -> %s",
                            _old_waf_base, _new_waf_base,
                        )
                    _ajax_body = _decoded.encode("utf-8")
                    _LOGGER.debug(
                        "Injected P shim + AJAX proxy into aaut/verify/cvf response (%d -> %d bytes)",
                        len(resp.content),
                        len(_ajax_body),
                    )
                except (UnicodeDecodeError, AttributeError, TypeError) as _e:
                    _LOGGER.warning("Failed to inject P shim into aaut response: %s", _e)
            _LOGGER.debug(
                "AJAX HTML response for %s - skipping modifiers",
                URL(str(request.url)).path,
            )
            # Forward original Amazon headers for AJAX responses.
            # The CVF JavaScript checks response headers (e.g., for CAPTCHA
            # initialization). Without them, it logs "ResponseHeader is null"
            # and the CAPTCHA never loads.
            _ajax_headers = self._filter_ajax_headers(resp) if resp is not None else {}
            return await self._build_response(
                resp, body=_ajax_body, content_type=content_type,
                headers=_ajax_headers,
            )
        # Also skip modifiers for non-HTML AJAX responses (JSON, binary, etc.)
        if _is_ajax and content_type != "text/html":
            _LOGGER.debug(
                "AJAX non-HTML response (%s) for %s - skipping modifiers",
                content_type,
                URL(str(request.url)).path,
            )
            _resp_body = resp.content
            _ajax_headers_nh = self._filter_ajax_headers(resp) if resp is not None else {}
            return await self._build_response(
                resp, body=_resp_body, content_type=content_type,
                headers=_ajax_headers_nh,
            )
        self.refresh_modifiers(URL(str(resp.url)))
        if self.modifiers:
            modified: bool = False
            if content_type != "text/html" and content_type not in self.modifiers.keys():
                text: Text = ""
            elif content_type != "text/html" and content_type in self.modifiers.keys():
                text = resp.text
            else:
                text = resp.text
            if not isinstance(text, str):  # process aiohttp text
                text = await resp.text()
            # Resolve relative form actions BEFORE modifiers run.
            # The modifiers (prepend_relative_urls) prepend the proxy base URL
            # but don't account for the response URL path. E.g., a form action
            # "verify" on page /ap/cvf/request should resolve to /ap/cvf/verify,
            # not just /verify.
            if text and content_type == "text/html" and resp and resp.url:
                _resp_url = URL(str(resp.url))
                _resp_dir = _resp_url.path.rsplit("/", 1)[0] + "/" if "/" in _resp_url.path else "/"

                def _resolve_form_action(form_match):
                    """Resolve relative action URLs only inside <form> tags."""
                    form_tag = form_match.group(0)
                    action_m = re.search(
                        r'(\s+action=["\'])([^"\']*?)(["\'])', form_tag
                    )
                    if not action_m:
                        return form_tag
                    action = action_m.group(2)
                    if action and not action.startswith(
                        ("http://", "https://", "//", "#", "javascript:", "/")
                    ):
                        resolved_path = _resp_dir + action
                        # Use PROXY URL (not Amazon URL) so the form submits
                        # through the proxy. The change_host_to_proxy modifier
                        # may not match if _host_url changed (e.g., amazon.it
                        # -> amazon.com redirect) since its partial has frozen
                        # parameters from the original host.
                        _proxy_base = self.access_url().path.rstrip("/")
                        abs_url = str(
                            self.access_url().with_path(
                                _proxy_base + resolved_path
                            ).with_query({})
                        )
                        _LOGGER.debug(
                            "Resolved relative form action '%s' -> '%s' (page: %s)",
                            action, abs_url, _resp_url.path,
                        )
                        return (
                            form_tag[: action_m.start(2)]
                            + abs_url
                            + form_tag[action_m.end(2) :]
                        )
                    return form_tag

                # Only resolve action= inside <form> tags to avoid corrupting
                # custom attributes like data-action, action on <div>, etc.
                text = re.sub(
                    r'<form\b[^>]*>',
                    _resolve_form_action,
                    text,
                    flags=re.IGNORECASE,
                )
            # Inject AJAX proxy script into CVF pages so that the aamation
            # challenge JavaScript can reach Amazon's servers through the proxy
            # instead of failing with NetworkError due to CORS/cross-origin.
            if (
                text
                and content_type == "text/html"
                and resp
                and "/ap/cvf/" in URL(str(resp.url)).path
            ):
                # Block CVF form auto-submit to give the CAPTCHA time to load.
                # The aamation JS sets EmptyResponse and auto-submits in ~24ms.
                # We block form.submit() until either:
                # a) The CAPTCHA is solved (aa-challenge-complete postMessage)
                # b) A fallback timeout expires (15 seconds)
                _submit_blocker_js = (
                    '<script>'
                    '(function(){'
                    'var _origSubmit=HTMLFormElement.prototype.submit;'
                    'var _blocked=true;'
                    'var _pendingForm=null;'
                    'HTMLFormElement.prototype.submit=function(){'
                    'if(_blocked){'
                    'console.log("[AMP] Form submit BLOCKED - waiting for CAPTCHA");'
                    '_pendingForm=this;'
                    'return;}'
                    'return _origSubmit.apply(this,arguments);};'
                    # Also intercept submit via button click / form.requestSubmit()
                    # IMPORTANT: Only block the CVF form, NOT the captcha's internal
                    # form. The captcha creates its own <form onSubmit=...> and if we
                    # stopPropagation here, the captcha's handler never fires and
                    # fetch("/verify") is never called.
                    'document.addEventListener("submit",function(e){'
                    'if(_blocked){'
                    'var f=e.target;'
                    'var isCVF=f&&f.querySelector&&f.querySelector("[name=cvf_aamation_response_token]");'
                    'if(isCVF){'
                    'e.preventDefault();e.stopPropagation();'
                    'console.log("[AMP] CVF form submit BLOCKED");'
                    '_pendingForm=f;'
                    'return false;}'
                    '}},true);'
                    # Unblock on aa-challenge-complete message from CAPTCHA iframe
                    # IMPORTANT: Do NOT submit the form immediately! ACIC needs to
                    # make an XHR to /aaut/verify/cvf to get the sessionToken, which
                    # must be set as cvf_aamation_response_token before submitting.
                    # We intercept XHR responses to /aaut/verify/cvf and extract the
                    # sessionToken from the amz-aamation-resp header.
                    'var _captchaVoucher=null;'
                    'var _waitingForAaut=false;'
                    # Override XHR send to watch for /aaut/verify/cvf responses
                    'var _origSend=XMLHttpRequest.prototype.send;'
                    'XMLHttpRequest.prototype.send=function(){'
                    'var xhr=this;'
                    'if(_waitingForAaut){'
                    'var xurl=xhr.__origUrl||"";'
                    'if(xurl.indexOf("/aaut/verify/cvf")!==-1){'
                    'xhr.addEventListener("load",function(){'
                    'try{'
                    'var aamResp=xhr.getResponseHeader("amz-aamation-resp");'
                    'if(aamResp){'
                    'var rd=JSON.parse(aamResp);'
                    'if(rd.sessionToken){'
                    'console.log("[AMP] Got sessionToken from aaut verify response");'
                    'var tok=document.querySelector("[name=cvf_aamation_response_token]");'
                    'if(tok){tok.value=rd.sessionToken;}'
                    'var err=document.querySelector("[name=cvf_aamation_error_code]");'
                    'if(err)err.value="";'
                    'var act=document.querySelector("[name=cvf_captcha_captcha_action]");'
                    'if(act)act.value="verifyAamationChallenge";'
                    # Also add clientSideContext - find form from DOM, not _pendingForm
                    'if(rd.clientSideContext){'
                    'var csc=decodeURIComponent(rd.clientSideContext);'
                    'var cscField=document.querySelector("[name=clientSideContext]");'
                    'if(!cscField){'
                    'var tokEl=document.querySelector("[name=cvf_aamation_response_token]");'
                    'var cvfForm=tokEl?(tokEl.closest?tokEl.closest("form"):tokEl.form):null;'
                    'if(cvfForm){'
                    'cscField=document.createElement("input");'
                    'cscField.type="hidden";cscField.name="clientSideContext";'
                    'cvfForm.appendChild(cscField);}}'
                    'if(cscField){cscField.value=csc;}'
                    '_waitingForAaut=false;'
                    '}}}'
                    'catch(e){console.error("[AMP] Error processing aaut response:",e);}'
                    '});'
                    '}}'
                    'return _origSend.apply(this,arguments);};'
                    # Message listener
                    'window.addEventListener("message",function(ev){'
                    'try{var d=JSON.parse(ev.data);'
                    'if(d.eventId==="aa-challenge-complete"){'
                    'console.log("[AMP] CAPTCHA solved! voucher="+d.payload.substring(0,80)+"...");'
                    '_blocked=false;'
                    '_captchaVoucher=d.payload;'
                    '_waitingForAaut=true;'
                    # Fallback: if ACIC XHR doesn't complete in 5s, submit with voucher
                    'setTimeout(function(){'
                    'if(_waitingForAaut){'
                    'console.log("[AMP] ACIC timeout - submitting form with voucher as fallback");'
                    'var tok=document.querySelector("[name=cvf_aamation_response_token]");'
                    'if(tok){'
                    'tok.value=_captchaVoucher;}'
                    'var err=document.querySelector("[name=cvf_aamation_error_code]");'
                    'if(err)err.value="";'
                    'var act=document.querySelector("[name=cvf_captcha_captcha_action]");'
                    'if(act)act.value="verifyAamationChallenge";'
                    'if(_pendingForm){_origSubmit.call(_pendingForm);}'
                    '_waitingForAaut=false;'
                    '}},5000);'
                    '}'
                    'if(d.eventId==="aa-challenge-loaded"){'
                    '}'
                    '}catch(e){}});'
                    # Fallback: unblock after 15 seconds
                    'setTimeout(function(){'
                    'if(_blocked){'
                    'console.log("[AMP] Fallback timeout - unblocking form submit");'
                    '_blocked=false;'
                    'if(_pendingForm){_origSubmit.call(_pendingForm);}'
                    '}},15000);'
                    '})();'
                    '</script>'
                )
                _ajax_proxy_js = (
                    '<script>'
                    '(function(){'
                    'var pp=window.location.pathname.split("/ap/")[0];'
                    'function rw(u){'
                    'try{var p=new URL(u,window.location.href);'
                    'if(p.hostname.match(/\\.(amazon\\.(com|it|co\\.uk|de|fr|es|co\\.jp|ca|com\\.au|in|com\\.br)|awswaf\\.com|amazoncognito\\.com|ssl-images-amazon\\.com)$/)){'
                    'if(p.hostname==="www.amazon.com"||p.hostname===window.location.hostname)'
                    'return pp+p.pathname+p.search;'
                    'return pp+"/__amzn_host__"+p.hostname+p.pathname+p.search;'
                    '}}catch(e){}return u;}'
                    'var xo=XMLHttpRequest.prototype.open;'
                    'XMLHttpRequest.prototype.open=function(m,u){'
                    'if(typeof u==="string"){this.__origUrl=u;arguments[1]=rw(u);}'
                    'return xo.apply(this,arguments);};'
                    'var _xrd=Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype,"responseURL");'
                    'if(_xrd&&_xrd.get){Object.defineProperty(XMLHttpRequest.prototype,"responseURL",{'
                    'get:function(){return this.__origUrl||_xrd.get.call(this);},configurable:true});}'
                    'var fo=window.fetch;'
                    'if(fo)window.fetch=function(i,n){'
                    'var orig=typeof i==="string"?i:i;'
                    'if(typeof i==="string")i=rw(i);'
                    'if(i===orig)return fo.call(this,i,n);'
                    'console.log("[AMP] fetch rewrite:",orig.substring(0,80),"->",i.substring(0,80));'
                    'return fo.call(this,i,n).then(function(r){'
                    'Object.defineProperty(r,"url",{value:orig,configurable:true});'
                    'return r;});};'
                    'var sb=navigator.sendBeacon;'
                    'if(sb)navigator.sendBeacon=function(u,d){'
                    'return sb.call(this,rw(u),d);};'
                    '})();'
                    '</script>'
                )
                # Insert before the very first <script> tag so our wrappers
                # are installed before any Amazon JavaScript runs.
                _script_pos = text.lower().find('<script')
                if _script_pos >= 0:
                    text = text[:_script_pos] + _submit_blocker_js + _ajax_proxy_js + text[_script_pos:]
                    _LOGGER.debug(
                        "Injected submit blocker + AJAX proxy into CVF page (%s)",
                        resp.url,
                    )
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
                return await self._build_response(
                    resp,
                    text=text,
                    content_type=content_type,
                )
        # pass through non parsed content
        _LOGGER.debug(
            "Passing through %s as %s",
            URL(str(request.url)).name
            if URL(str(request.url)).name
            else URL(str(request.url)).path,
            content_type,
        )
        return await self._build_response(resp, body=resp.content, content_type=content_type)

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
        if self.session:
            _LOGGER.debug("Closing session")
            await self.session.aclose()
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
            self.access_url() if not domain_only else self.access_url().with_path("/"))
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

    async def modify_headers(self, site: URL, request: web.Request) -> dict:
        """Modify headers.

        Return modified headers based on site and request. To disable auto header generation,
        pass in to the header a key const.SKIP_AUTO_HEADERS with a list of keys to not generate.

        For example, to prevent User-Agent generation: {SKIP_AUTO_HEADERS : ["User-Agent"]}

        Args:
            site (URL): URL of the next host request.
            request (web.Request): Proxy directed request. This will need to be changed for the actual host request.

        Returns:
            dict: Headers after modifications
        """
        result: Dict[str, Any] = {}
        result.update(request.headers)
        # _LOGGER.debug("Original headers %s", headers)
        if result.get("Host"):
            result.pop("Host")
        if result.get("Origin"):
            # Always use the Amazon host as Origin, not the target site.
            # For third-party services (e.g., awswaf.com CAPTCHA verify),
            # Origin must match the page that loaded the script (Amazon).
            result["Origin"] = f"{self._host_url.with_path('')}"
        # remove any cookies in header received from browser. If not removed, httpx will not send session cookies
        if result.get("Cookie"):
            result.pop("Cookie")
        if result.get("Referer") and (
            URL(result.get("Referer", "")).query == self.init_query
            or URL(result.get("Referer", "")).path
            == "/config/integrations"  # home-assistant referer
        ):
            # Change referer for starting request; this may have query items we shouldn't pass
            result["Referer"] = str(self._host_url)
        elif result.get("Referer"):
            result["Referer"] = self._swap_proxy_and_host(
                result.get("Referer", ""), domain_only=True
            )
        for item in [
            "Content-Length",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Port",
            "X-Forwarded-Proto",
            "X-Forwarded-Scheme",
            "X-Forwarded-Server",
            "X-Real-IP",
        ]:
            # remove proxy headers
            if result.get(item):
                result.pop(item)
        result.update(self.headers if self.headers else {})
        _LOGGER.debug("Final headers %s", result)
        return result

    def check_redirects(self) -> None:
        """Change host if redirect detected and regex does not match self.redirect_filters.

        Self.redirect_filters is a dict with key as attr in resp and value as list of regex expressions to filter against.
        """
        if not self.last_resp:
            return
        resp: httpx.Response = self.last_resp
        if resp.history:
            for item in resp.history:
                if (
                    item.status_code in [301, 302, 303, 304, 305, 306, 307, 308]
                    and item.url
                    and resp.url
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
                        item.status_code,
                        item.url.host,
                        resp.url.host,
                    )
                    self._host_url = self._host_url.with_host(resp.url.host)
