#  SPDX-License-Identifier: Apache-2.0
"""
Python Package for auth capture proxy.

Example modifiers.
"""
from typing import Text
from bs4 import BeautifulSoup
import logging

_LOGGER = logging.getLogger(__name__)


def autofill(items: dict, html: Text) -> Text:
    """Autofill input tags in form.

    WARNING: This modifier does not obfuscate debug logs.

    Args:
        items (dict): Dictionary of values to fill. The key the name or id of the form input to fill and the value is the value.
        html (Text): html to convert

    Returns:
        Text: html with values filled in

    """
    soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
    if not soup:
        _LOGGER.debug("Soup is empty")
        return ""
    if not items:
        _LOGGER.debug("No items specified; no modifications made")
        return html
    for item, value in items.items():
        for html_tag in soup.find_all(attrs={"name": item}) + soup.find_all(attrs={"id": item}):
            html_tag["value"] = value
            _LOGGER.debug(
                "Filled %s",
                str(html_tag).replace(
                    value,
                ),
            )
    return str(soup)
