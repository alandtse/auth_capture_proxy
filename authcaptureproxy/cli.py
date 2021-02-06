#  SPDX-License-Identifier: Apache-2.0
"""
Command-line interface for auth_capture_proxy.
"""

from __future__ import annotations

import asyncio
import logging
import time
from functools import partial, wraps
from typing import Any, Dict, Optional, Text

import typer
from aiohttp import ClientResponse
from yarl import URL

from authcaptureproxy import AuthCaptureProxy, __copyright__, __title__, __version__, metadata
from authcaptureproxy.examples.modifiers import autofill

logger = logging.getLogger(__package__)
cli = typer.Typer()


def coro(f):
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
        for value in progress:
            time.sleep(n_seconds)
            total += 1
    typer.echo(f"Processed {total} things.")


@cli.command()
@coro
async def proxy_example(
    proxy: str = "http://127.0.0.1",
    host: str = "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&",
    callback: str = "",
):
    """Run proxy example for Amazon.com.

    Args:
        proxy (str, optional): The url to connect to the proxy. If no port specified, will generate random port. Defaults to "http://127.0.0.1".
        host (str, optional): The signing page to proxy. Defaults to "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F%3Fref_%3Dnav_signin&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&".
        callback (str, optional): Callback url to redirect browser to on success. Defaults to "".

    """
    proxy_url = None
    host_url = None
    callback_url = None
    if proxy:
        proxy_url = URL(proxy)
    if host:
        host_url = URL(host)
    if callback:
        callback_url = URL(callback)
    proxy = AuthCaptureProxy(proxy_url=proxy_url, host_url=host_url)

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
        if str(resp.url) == "https://www.amazon.com/?ref_=nav_signin&":
            # save any needed info from resp, data, or query
            # cookies will be in proxy.session.cookie_jar
            asyncio.create_task(proxy.stop_proxy(3))  # stop proxy in 3 seconds
            if callback_url:
                return URL(callback_url)  # 302 redirect
            return f"Successfully logged in {data.get('email')} and {data.get('password')}. Please close the window."

    # add tests. See :mod:`authcaptureproxy.examples.testers`.
    proxy.tests = {"test_url": test_url}

    # add modifiers like autofill to manipulate html returned to browser. See :mod:`authcaptureproxy.examples.modifiers`.
    proxy.modifiers = {
        "autofill": partial(
            autofill,
            {
                "password": "CHANGEME",
            },
        )
    }

    await proxy.start_proxy()
    # connect to proxy at proxy.access_url and sign in
    typer.echo(
        f"Launching browser to connect to proxy at {proxy.access_url()} and sign in using logged-out account."
    )
    typer.launch(str(proxy.access_url()))

    # set proxy to close in 5 minutes
    await proxy.stop_proxy(delay=300)
    # or stop the proxy when done manually


if __name__ == "__main__":
    cli()
