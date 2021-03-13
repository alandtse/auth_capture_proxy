#  SPDX-License-Identifier: Apache-2.0
"""Command-line interface for auth_capture_proxy."""

from __future__ import annotations

import asyncio
import datetime
import json
import logging
import sys
import time
from functools import partial, wraps
from typing import Any, Dict, Text

import typer
from aiohttp import ClientResponse
from yarl import URL

from authcaptureproxy import AuthCaptureProxy, __copyright__, __title__, __version__, metadata
from authcaptureproxy.examples.modifiers import autofill

logger = logging.getLogger(__package__)
cli = typer.Typer()


def coro(f):
    """Wrap f to run as async."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@cli.command()
def info(n_seconds: float = 0.01, verbose: bool = False) -> None:
    """
    Get info about auth_capture_proxy.

    Args:
        n_seconds: Number of seconds to wait between processing.
        verbose: Output more info
    """
    typer.echo(f"{__title__} version {__version__}, {__copyright__}")
    if verbose:
        typer.echo(str(metadata.__dict__))
    total = 0
    with typer.progressbar(range(100)) as progress:
        for _ in progress:
            time.sleep(n_seconds)
            total += 1
    typer.echo(f"Processed {total} things.")


@cli.command()
@coro
async def proxy_example(
    proxy: str = "http://127.0.0.1",
    host: str = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&",
    callback: str = "",
    timeout: int = 300,
    debug: bool = False,
):
    """Run proxy example for Amazon.com.

    Args:
        proxy (str, optional): The url to connect to the proxy. If no port specified, will generate random port. Defaults to "http://127.0.0.1".
        host (str, optional): The signing page to proxy. Defaults to "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&".
        callback (str, optional): Callback url to redirect browser to on success. Defaults to "".
        timeout (int, optional): How long to leave the proxy running without success. Defaults to 300.
        debug (bool, optional): Whether to print debug messages to console. Defaults to False.

    """
    if debug:
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    proxy_url = URL()
    host_url = URL()
    callback_url = URL()
    if proxy:
        proxy_url = URL(proxy)
    if host:
        host_url = URL(host)
    if callback:
        callback_url = URL(callback)
    proxy_obj: AuthCaptureProxy = AuthCaptureProxy(proxy_url=proxy_url, host_url=host_url)

    def test_url(resp: ClientResponse, data: Dict[Text, Any], query: Dict[Text, Any]):
        """Test for a successful Amazon URL.

        Args:
            resp (ClientResponse): The aiohttp response.
            data (Dict[Text, Any]): Dictionary of all post data captured through proxy with overwrites for duplicate keys.
            query (Dict[Text, Any]): Dictionary of all query data with overwrites for duplicate keys.

        Returns:
            Optional[Union[URL, Text]]: URL for a http 302 redirect or Text to display on success. None indicates test did not pass.
        """
        # Did we reach specific url?
        typer.echo(f"URL {resp.url}")
        if "https://www.amazon.com/?ref_=nav_signin" in str(resp.url):
            # save any needed info from resp, data, or query
            # cookies will be in proxy.session.cookie_jar
            asyncio.create_task(proxy_obj.stop_proxy(3))  # stop proxy in 3 seconds
            if callback_url:
                return URL(callback_url)  # 302 redirect
            return f"Successfully logged in {data.get('email')} and {data.get('password')}. Please close the window.<br /><b>Post data</b><br />{json.dumps(data)}<br /><b>Query Data:</b><br />{json.dumps(query)}<br /><b>Cookies:</b></br>{proxy_obj.session.cookie_jar.filter_cookies(proxy_obj._host_url.with_path('/'))}"

    await proxy_obj.start_proxy()
    # add tests and modifiers after the proxy has started so that port data is available for self.access_url()
    # add tests. See :mod:`authcaptureproxy.examples.testers`.
    proxy_obj.tests = {"test_url": test_url}

    # add modifiers like autofill to manipulate html returned to browser. See :mod:`authcaptureproxy.examples.modifiers`.
    # this will add to any default modifiers
    proxy_obj.modifiers.update(
        {
            "text/html": {
                "autofill": partial(
                    autofill,
                    {
                        "password": "CHANGEME",
                    },
                )
            }
        }
    )
    # add filter to redirect check. Filter out all urls from redirect check.
    proxy_obj.redirect_filters = {"url": ["^.*$"]}

    # connect to proxy at proxy.access_url() and sign in
    typer.echo(
        f"Launching browser to connect to proxy at {proxy_obj.access_url()} and sign in using logged-out account."
    )
    typer.launch(str(proxy_obj.access_url()))
    typer.echo(f"Proxy will timeout and close in {datetime.timedelta(seconds=timeout)}.")
    asyncio.create_task(proxy_obj.stop_proxy(timeout))
    # or stop the proxy when done manually
    while proxy_obj.active:
        # loop until proxy done
        await asyncio.sleep(1)
    typer.echo("Proxy completed; exiting")
    raise typer.Exit()


if __name__ == "__main__":
    cli()
