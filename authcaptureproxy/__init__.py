#  SPDX-License-Identifier: Apache-2.0
"""Metadata for this auth_capture_proxy."""

from __future__ import annotations

import logging
from pathlib import Path
from importlib.metadata import PackageNotFoundError, PackageMetadata, metadata as __load

from authcaptureproxy import const
from authcaptureproxy.auth_capture_proxy import AuthCaptureProxy
from authcaptureproxy.examples.modifiers import find_regex_urls
from authcaptureproxy.helper import prepend_url, swap_url
from authcaptureproxy.interceptor import BaseInterceptor, InterceptContext
from authcaptureproxy.stackoverflow import return_timer_countdown_refresh_html

pkg = Path(__file__).absolute().parent.name
logger = logging.getLogger(pkg)

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

metadata: PackageMetadata | None = None

try:
    md = __load(pkg)    # md is PackageMetadata (non-optional)
    metadata = md            # keep public handle

    __uri__ = md.get("Home-page") or metadata.get("Home-Page") or ""
    __title__ = md.get("Name") or ""
    __summary__ = md.get("Summary") or ""
    __license__ = md.get("License") or ""
    __version__ = md.get("Version") or ""
    __author__ = md.get("Author") or ""
    __maintainer__ = md.get("Maintainer") or ""

    __contact__ = (
        md.get("Author-email")
        or md.get("Maintainer-email")
        or md.get("Author-email".lower())          # harmless fallback if casing differs
        or md.get("Maintainer-email".lower())
        or md.get("Maintainer")
        or ""
    )

except PackageNotFoundError:  # pragma: no cover
    logger.error("Could not load package metadata for %s. Is it installed?", pkg)

if __name__ == "__main__":  # pragma: no cover
    if metadata is not None:
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
    "metadata",
]
