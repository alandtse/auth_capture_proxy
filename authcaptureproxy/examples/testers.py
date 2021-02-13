#  SPDX-License-Identifier: Apache-2.0
"""
Python Package for auth capture proxy.

Example testers.
"""

from typing import Any, Dict, Optional, Text, Union

from aiohttp.client_reqrep import ClientResponse
from yarl import URL


def test_amazon(
    self, resp: ClientResponse, data: Dict[Text, Any], query: Dict[Text, Any]
) -> Optional[Union[URL, Text]]:
    """Test Amazon login example.

    This is a simplifed example based on alexapy. https://gitlab.com/keatontaylor/alexapy/-/blob/dev/alexapy/alexaproxy.py

    Args:
        resp (ClientResponse): The aiohttp response.
        data (Dict[Text, Any]): Dictionary of all post data captured through proxy with overwrites for duplicate keys.
        query (Dict[Text, Any]): Dictionary of all query data with overwrites for duplicate keys.

    Returns:
        Optional[Union[URL, Text]]: URL for a http 302 redirect or Text to display on success. None indicates test did not pass.
    """
    if resp.url.path in ["/ap/maplanding", "/spa/index.html"]:
        access_token = resp.url.query.get("openid.oa2.access_token")
        config_flow_id = self.init_query.get("config_flow_id")
        callback_url = self.init_query.get("callback_url")
        if callback_url:
            return URL(callback_url)
        return f"Successfully received token:{access_token} for flow {config_flow_id}. Please close the window."
    return None
