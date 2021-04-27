"""Test the auth_capture proxy helper."""
from httpx import Response
from multidict import MultiDict, MultiDictProxy
from yarl import URL

import authcaptureproxy.helper as helper

EMPTY_URL = URL("")
VALID_URL = URL("http://www.google.com")
RELATIVE_URL = URL("/test/asdf")
ABSOLUTE_URL = URL("http://example.com")
TEST_DICT = {"a": "b", "b": 9}
TEST_MULTIDICT = MultiDict(TEST_DICT)
DICT_WITH_REPEAT = {"a": ["b", "abc"], "b": 9}
TEST_MULTIDICT_WITH_REPEAT = MultiDict(TEST_DICT)
TEST_MULTIDICT_WITH_REPEAT.add("a", "abc")


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


def test_get_content_type():
    """Test ability to pull content_type correctly."""
    # upper case
    assert (
        helper.get_content_type(Response(status_code=200, headers={"Content-Type": "text/html"}))
        == "text/html"
    )
    # lower case
    assert (
        helper.get_content_type(Response(status_code=200, headers={"content-type": "text/html"}))
        == "text/html"
    )
    # spaces
    assert (
        helper.get_content_type(
            Response(status_code=200, headers={"Content-Type": "application/json; charset=utf-8"})
        )
        == "application/json"
    )
    # no spaces
    assert (
        helper.get_content_type(
            Response(status_code=200, headers={"Content-Type": "application/json;charset=utf-8"})
        )
        == "application/json"
    )


def test_convert_multidict_to_dict():
    """Test conversion fo multidict to dict."""
    assert TEST_DICT == helper.convert_multidict_to_dict(TEST_MULTIDICT)
    assert TEST_DICT == helper.convert_multidict_to_dict(MultiDictProxy(TEST_MULTIDICT))
    assert DICT_WITH_REPEAT == helper.convert_multidict_to_dict(TEST_MULTIDICT_WITH_REPEAT)
