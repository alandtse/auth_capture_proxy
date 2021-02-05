#  SPDX-License-Identifier: CC-BY-SA-4.0
"""
Python Package auth capture proxy.

This is code borrowed from stack overflow.
"""
import socket


def get_open_port() -> int:
    """Get random open port.

    https://stackoverflow.com/questions/2838244/get-open-tcp-port-in-python/2838309#2838309
    Returns
        int: a random open port. This does not guarantee the port will remain open and may fail if there is a race condition.
    """

    # pylint: disable=invalid-name

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port
