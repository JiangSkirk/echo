"""AppShell Personal/Work share 127.0.0.1 but different ports.

Browsers scope cookies by host, not port. A shared ``js_session`` cookie
name therefore lets Work login overwrite Personal (and vice versa), which
surfaces as “断开 - 重连中” after every product switch.
"""

from __future__ import annotations

from js.web.auth import resolve_session_cookie, session_cookie_name


def test_session_cookie_names_are_product_scoped() -> None:
    assert session_cookie_name("js-agent") == "js_session_js-agent"
    assert session_cookie_name("js-work") == "js_session_js-work"
    assert session_cookie_name("js-agent") != session_cookie_name("js-work")


def test_work_does_not_accept_personal_or_legacy_cookie() -> None:
    personal_token = "personal-token"
    legacy = {"js_session": personal_token}
    personal_scoped = {"js_session_js-agent": personal_token}
    assert resolve_session_cookie(legacy, "js-agent") == personal_token
    assert resolve_session_cookie(personal_scoped, "js-agent") == personal_token
    assert resolve_session_cookie(legacy, "js-work") is None
    assert resolve_session_cookie(personal_scoped, "js-work") is None


def test_product_cookies_coexist_without_clobber() -> None:
    """Simulate a browser cookie jar after logging into both products."""
    jar = {
        "js_session_js-agent": "tok-personal",
        "js_session_js-work": "tok-work",
    }
    assert resolve_session_cookie(jar, "js-agent") == "tok-personal"
    assert resolve_session_cookie(jar, "js-work") == "tok-work"
    # Overwriting Work must not change Personal resolution.
    jar["js_session_js-work"] = "tok-work-2"
    assert resolve_session_cookie(jar, "js-agent") == "tok-personal"
    assert resolve_session_cookie(jar, "js-work") == "tok-work-2"
