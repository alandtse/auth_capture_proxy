#  SPDX-License-Identifier: Apache-2.0
"""
Copyright 2021 Alan D. Tse.

"""
import pytest

from authcaptureproxy import __copyright__
from authcaptureproxy import cli


class TestCli:
    """Tests CLI interface."""

    def test_cli(self, capsys):
        """Test CLI dummy output."""
        cli.info()
        out, _ = capsys.readouterr()
        assert __copyright__ in out


if __name__ == "__main__":
    pytest.main()
