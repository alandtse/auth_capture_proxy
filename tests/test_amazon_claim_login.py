"""Synthetic Amazon split-login regressions; no Amazon network requests."""

from urllib.parse import parse_qs

import httpx
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from bs4 import BeautifulSoup
from yarl import URL

from authcaptureproxy import AuthCaptureProxy


def _form(action, field, app_action):
    return (
        f'<form name="signIn" method="post" action="{action}">'
        f'<input type="hidden" name="appAction" value="{app_action}">'
        '<input type="hidden" name="workflowState" value="synthetic-state">'
        f'<input name="{field}"><button type="submit">Continue</button></form>'
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("domain", ["www.amazon.com", "www.amazon.co.uk"])
@pytest.mark.parametrize(
    "password_action",
    ["/ap/signin", "absolute", "../ap/signin?arb=PWD&amp;step=2", "?arb=PWD&amp;step=2"],
)
async def test_claim_then_password(domain, password_action):
    """Rewrite both forms and retain redirect cookies and each submitted payload."""
    origin = f"https://{domain}"
    if password_action == "absolute":  # nosec B105 - synthetic test value
        password_action = origin + "/ap/signin"
    calls = []

    def upstream(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                302,
                headers={
                    "Location": "/ap/signin?stage=email",
                    "Set-Cookie": "session-id=synthetic; Path=/; Secure",
                },
            )
        if len(calls) == 2:
            return httpx.Response(
                200, text=_form("/ax/claim?arb=EMAIL&amp;step=1", "email", "SIGNIN_CLAIM_COLLECT")
            )
        if len(calls) == 3:
            return httpx.Response(
                200,
                text=_form(password_action, "password", "SIGNIN_PWD_COLLECT"),
                headers={"Set-Cookie": "claim-token=synthetic; Path=/; Secure"},
            )
        return httpx.Response(200, text='<input name="otpCode">')

    def html_upstream(request):
        response = upstream(request)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        return response

    # Use a real HTTPX client so redirects, method selection and cookie scoping run.
    async with httpx.AsyncClient(transport=httpx.MockTransport(html_upstream)) as session:
        proxy = AuthCaptureProxy(
            URL("http://127.0.0.1/proxy"), URL(origin + "/ap/register"), session=session
        )
        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", proxy.all_handler)
        async with TestClient(TestServer(app)) as browser:
            proxy._proxy_url = browser.make_url("/proxy")
            headers = {"Sec-Fetch-Mode": "navigate", "Cookie": "ha-session=must-not-forward"}
            response = await browser.get("/proxy", headers=headers)
            for field, value, action in [
                ("email", "synthetic@example.invalid", "SIGNIN_CLAIM_COLLECT"),
                ("password", "synthetic-password", "SIGNIN_PWD_COLLECT"),
            ]:
                assert response.status == 200
                assert "Set-Cookie" not in response.headers
                form = BeautifulSoup(await response.text(), "html.parser").find("form")
                target = URL(form["action"])
                assert target.origin() == proxy.access_url().origin()
                expected = URL(origin + "/ax/claim?arb=EMAIL&step=1")
                if field == "password":
                    expected = expected.join(URL(password_action.replace("&amp;", "&")))
                assert target.path == "/proxy" + expected.path
                assert target.query == expected.query
                payload = {tag["name"]: tag.get("value", "") for tag in form.find_all("input")}
                payload[field] = value
                assert payload["appAction"] == action
                response = await browser.post(target.path_qs, data=payload, headers=headers)
            assert 'name="otpCode"' in await response.text()

    assert [req.method for req in calls] == ["GET", "GET", "POST", "POST"]
    assert str(calls[2].url) == origin + "/ax/claim?arb=EMAIL&step=1"
    assert str(calls[3].url) == str(expected)
    email_data = parse_qs(calls[2].content.decode())
    password_data = parse_qs(calls[3].content.decode())
    assert email_data == {
        "email": ["synthetic@example.invalid"],
        "appAction": ["SIGNIN_CLAIM_COLLECT"],
        "workflowState": ["synthetic-state"],
    }
    assert password_data == {
        "password": ["synthetic-password"],
        "appAction": ["SIGNIN_PWD_COLLECT"],
        "workflowState": ["synthetic-state"],
    }
    assert "session-id=synthetic" in calls[2].headers["cookie"]
    assert "claim-token=synthetic" in calls[3].headers["cookie"]
    assert all("ha-session" not in req.headers.get("cookie", "") for req in calls)
