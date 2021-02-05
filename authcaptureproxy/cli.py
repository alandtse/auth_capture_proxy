#  SPDX-License-Identifier: Apache-2.0
"""
Command-line interface for auth_capture_proxy.
"""

from __future__ import annotations

import logging
import time

import typer

from authcaptureproxy import __title__, __version__, __copyright__, metadata


logger = logging.getLogger(__package__)
cli = typer.Typer()


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


if __name__ == "__main__":
    cli()
