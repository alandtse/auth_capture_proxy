"""Test the auth_capture_proxy stackoverflow."""
import random
import string
from unittest.mock import patch

from bs4 import BeautifulSoup as bs  # type: ignore

from authcaptureproxy.stackoverflow import get_open_port, return_timer_countdown_refresh_html


def test_get_open_port():
    """Test get_open_port."""
    with patch(
        "authcaptureproxy.stackoverflow.socket.socket.getsockname",
        return_value=["0.0.0.0", 1234],  # nosec
    ) as getsockname:
        with patch("authcaptureproxy.stackoverflow.socket.socket.bind", autospec=True) as bind:
            with patch(
                "authcaptureproxy.stackoverflow.socket.socket.listen", autospec=True
            ) as listen:
                # mock_socket = mock_socket.return_value
                # mock_socket.socket.getsockname.return_value = ["0.0.0.0", 1]
                port = get_open_port()
                getsockname.assert_called_with()
                bind.assert_called_with(("", 0))
                listen.assert_called_with(1)
                assert port == 1234


def test_return_timer_countdown_refresh_html():
    """Test return_timer_countdown_refresh_html with random content."""
    for _ in range(10):
        seconds = random.randint(0, 10000000)  # nosec
        text = "".join(
            random.choice(string.ascii_letters + string.digits)  # nosec
            for _ in range(random.randint(0, 200))  # nosec
        )
        hard_refresh = seconds % 2 == 0
        result = return_timer_countdown_refresh_html(seconds, text, hard_refresh)
        soup = bs(result, "html.parser")
        assert soup.find("script", defer="defer")
        assert soup.find("script", defer="defer").contents[0].endswith(f"""({seconds});""")
        assert (
            soup.find("script", defer="defer")
            .contents[0]
            .find(f"""location.reload({str(hard_refresh).lower()});""")
            > 0
        )
        assert soup.find("body")
        if text:
            assert len(soup.find("body").contents) == 2
            assert soup.find("body").contents[0] == text
            assert soup.find("body").contents[1].name == "div"
            assert soup.find("body").contents[1]["id"] == "countdown"
        else:
            assert len(soup.find("body").contents) == 1
            assert soup.find("body").contents[0].name == "div"
            assert soup.find("body").contents[0]["id"] == "countdown"


def test_return_timer_countdown_refresh_html_empty_string():
    """Test return_timer_countdown_refresh_html with null content."""
    for _ in range(10):
        seconds = random.randint(0, 10000000)  # nosec
        text = ""
        hard_refresh = seconds % 2 == 0
        result = return_timer_countdown_refresh_html(seconds, text, hard_refresh)
        soup = bs(result, "html.parser")
        assert soup.find("script", defer="defer")
        assert soup.find("script", defer="defer").contents[0].endswith(f"""({seconds});""")
        assert (
            soup.find("script", defer="defer")
            .contents[0]
            .find(f"""location.reload({str(hard_refresh).lower()});""")
            > 0
        )
        assert soup.find("body")
        assert len(soup.find("body").contents) == 1
        assert soup.find("body").contents[0].name == "div"
        assert soup.find("body").contents[0]["id"] == "countdown"


def test_return_timer_countdown_refresh_html_non_empty_string():
    """Test return_timer_countdown_refresh_html with random content."""
    for _ in range(10):
        seconds = random.randint(0, 10000000)  # nosec
        text = "".join(
            random.choice(string.ascii_letters + string.digits)  # nosec
            for _ in range(random.randint(1, 200))  # nosec
        )
        hard_refresh = seconds % 2 == 0
        result = return_timer_countdown_refresh_html(seconds, text, hard_refresh)
        soup = bs(result, "html.parser")
        assert soup.find("script", defer="defer")
        assert soup.find("script", defer="defer").contents[0].endswith(f"""({seconds});""")
        assert (
            soup.find("script", defer="defer")
            .contents[0]
            .find(f"""location.reload({str(hard_refresh).lower()});""")
            > 0
        )
        assert soup.find("body")
        assert len(soup.find("body").contents) == 2
        assert soup.find("body").contents[0] == text
        assert soup.find("body").contents[1].name == "div"
        assert soup.find("body").contents[1]["id"] == "countdown"
