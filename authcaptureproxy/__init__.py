#  SPDX-License-Identifier: Apache-2.0
"""Metadata for this auth_capture_proxy."""

import logging
from importlib.metadata import PackageNotFoundError
from importlib.metadata import metadata as __load
from pathlib import Path

from authcaptureproxy import const
from authcaptureproxy.auth_capture_proxy import AuthCaptureProxy
from authcaptureproxy.examples.modifiers import find_regex_urls
from authcaptureproxy.helper import prepend_url, swap_url
from authcaptureproxy.interceptor import BaseInterceptor, InterceptContext
from authcaptureproxy.stackoverflow import return_timer_countdown_refresh_html

pkg = Path(__file__).absolute().parent.name
logger = logging.getLogger(pkg)
metadata = None
try:
    metadata = __load(pkg)
    __status__ = "Development"
    __copyright__ = "Copyright 2021"
    __date__ = "2021-02-03"
    __uri__ = metadata.get("home-page") or metadata.get("Home-Page", "")
    __title__ = metadata["name"]
    __summary__ = metadata["summary"]
    __license__ = metadata["license"]
    __version__ = metadata["version"]
    __author__ = metadata["author"]
    __maintainer__ = metadata["maintainer"]
    __contact__ = metadata["maintainer"]
except PackageNotFoundError:  # pragma: no cover
    logger.error(f"Could not load package metadata for {pkg}. Is it installed?")

if __name__ == "__main__":  # pragma: no cover
    if metadata is not None:
        print(f"{pkg} (v{metadata['version']})")
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
