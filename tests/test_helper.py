"""Test the auth_capture proxy helper."""
from unittest.mock import patch

from yarl import URL

import authcaptureproxy.helper as helper

EMPTY_URL = URL("")
VALID_URL = URL("http://www.google.com")
RELATIVE_URL = URL("/test/asdf")
ABSOLUTE_URL = URL("http://example.com")


def test_prepend_url():
    """Test that url is prepended for relative urls only."""
    assert helper.prepend_url(VALID_URL, RELATIVE_URL) == VALID_URL.with_path(RELATIVE_URL.path)
    assert helper.prepend_url(VALID_URL, ABSOLUTE_URL) == ABSOLUTE_URL


def test_prepend_url_strings():
    """Test that url is prepended for relative urls only."""
    assert helper.prepend_url(str(VALID_URL), str(RELATIVE_URL)) == VALID_URL.with_path(
        RELATIVE_URL.path
    )
    assert helper.prepend_url(str(VALID_URL), str(ABSOLUTE_URL)) == ABSOLUTE_URL


def test_replace_empty_url_with_strings():
    """Test replace empty_url replaces empty urls."""

    assert VALID_URL == helper.replace_empty_url(str(VALID_URL), str(VALID_URL))
    assert VALID_URL == helper.replace_empty_url(str(VALID_URL), str(EMPTY_URL))
    assert VALID_URL == helper.replace_empty_url(
        str(EMPTY_URL),
        str(VALID_URL),
    )
    assert EMPTY_URL == helper.replace_empty_url(str(EMPTY_URL), str(EMPTY_URL))


def test_replace_empty_url():
    """Test replace empty_url replaces empty urls with string arguments."""

    assert VALID_URL == helper.replace_empty_url(VALID_URL, VALID_URL)
    assert VALID_URL == helper.replace_empty_url(VALID_URL, EMPTY_URL)
    assert VALID_URL == helper.replace_empty_url(
        EMPTY_URL,
        VALID_URL,
    )
    assert EMPTY_URL == helper.replace_empty_url(EMPTY_URL, EMPTY_URL)
