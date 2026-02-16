#  SPDX-License-Identifier: Apache-2.0
"""Metadata for this auth_capture_proxy."""

from __future__ import annotations

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

# Always define dunders so importing them never raises NameError
__status__ = "Development"
__copyright__ = "Copyright 2021"
__date__ = "2021-02-03"

__uri__ = ""
__title__ = ""
__summary__ = ""
__license__ = ""
__version__ = ""
__author__ = ""
__maintainer__ = ""
__contact__ = ""

_metadata: Message | None = None

try:
    _metadata = __load(pkg)

    # Canonical metadata header names are Title-Case
    __uri__ = _metadata.get("Home-page") or _metadata.get("Home-Page") or ""
    __title__ = _metadata.get("Name") or ""
    __summary__ = _metadata.get("Summary") or ""
    __license__ = _metadata.get("License") or ""
    __version__ = _metadata.get("Version") or ""
    __author__ = _metadata.get("Author") or ""
    __maintainer__ = _metadata.get("Maintainer") or ""

    # Prefer an email header for contact, with sensible fallbacks
    __contact__ = (
        _metadata.get("Author-email")
        or _metadata.get("Maintainer-email")
        or _metadata.get("Maintainer")
        or ""
    )

except PackageNotFoundError:  # pragma: no cover
    logger.error("Could not load package metadata for %s. Is it installed?", pkg)

if __name__ == "__main__":  # pragma: no cover
    if _metadata is not None:
        print(f"{pkg} (v{__version__})")
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
