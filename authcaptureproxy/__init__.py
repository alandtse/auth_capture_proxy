#  SPDX-License-Identifier: Apache-2.0
"""Metadata for this auth_capture_proxy."""

from email.message import Message
from importlib.metadata import PackageNotFoundError, metadata as __load
import logging
from pathlib import Path

from authcaptureproxy import const
from authcaptureproxy.auth_capture_proxy import AuthCaptureProxy
from authcaptureproxy.examples.modifiers import find_regex_urls
from authcaptureproxy.helper import prepend_url, swap_url
from authcaptureproxy.interceptor import BaseInterceptor, InterceptContext
from authcaptureproxy.stackoverflow import return_timer_countdown_refresh_html

pkg = Path(__file__).absolute().parent.name
logger = logging.getLogger(pkg)
metadata: Message | None = None

try:
    metadata = __load(pkg)

    __status__ = "Development"
    __copyright__ = "Copyright 2021"
    __date__ = "2021-02-03"

    # Use canonical metadata headers; keep a fallback for older variants.
    __uri__ = metadata.get("Home-page") or metadata.get("Home-Page") or ""
    __title__ = metadata.get("Name") or ""
    __summary__ = metadata.get("Summary") or ""
    __license__ = metadata.get("License") or ""
    __version__ = metadata.get("Version") or ""
    __author__ = metadata.get("Author") or ""
    __maintainer__ = metadata.get("Maintainer") or ""
    __contact__ = metadata.get("Maintainer") or ""

except PackageNotFoundError:  # pragma: no cover
    logger.error("Could not load package metadata for %s. Is it installed?", pkg)

if __name__ == "__main__":  # pragma: no cover
    if metadata is not None:
        print(f"{pkg} (v{metadata.get('Version', '')})")
    else:
        print(f"Unknown project info for {pkg}")


__all__ = [
    "AuthCaptureProxy",
    "BaseInterceptor",
    "InterceptContext",
    "const",
    "return_timer_countdown_refresh_html",
    "find_regex_urls",
    "prepend_url",
    "swap_url",
]
