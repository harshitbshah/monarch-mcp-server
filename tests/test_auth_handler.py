"""Auth handler unit tests.

Covers _AuthHandler routing (do_GET, do_POST), cookie login logic,
_send_json/_send_html helpers, log_message, _find_free_port,
and _validate_credential.
"""
# pylint: disable=missing-function-docstring,protected-access

import io
import json
from unittest.mock import patch, Mock, MagicMock

import pytest
from monarchmoney import LoginFailedException

from monarch_mcp.auth_server import (
    _AuthHandler,
    _AuthState,
    _find_free_port,
    _validate_credential,
)


# ── Handler factory ───────────────────────────────────────────────


def _make_handler(
    path="/",
    method="GET",
    body=None,
    *,
    expected_port=8080,
    content_type="application/json",
    host="127.0.0.1:8080",
    origin="http://127.0.0.1:8080",
):
    """Create an _AuthHandler wired for unit testing without sockets.

    Defaults produce a same-origin, JSON request that passes the
    Host/Origin/Content-Type guards.  Pass ``None`` for ``content_type``,
    ``host``, or ``origin`` to omit that header.
    """
    handler = object.__new__(_AuthHandler)
    handler.auth_state = _AuthState()
    handler.expected_port = expected_port
    handler.path = path

    # Wire up the response plumbing
    handler.wfile = io.BytesIO()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.send_error = Mock()

    # Wire up request body for POST
    if body is not None:
        raw = json.dumps(body).encode() if isinstance(body, dict) else body
        handler.rfile = io.BytesIO(raw)
        content_length = str(len(raw))
    else:
        handler.rfile = io.BytesIO(b"")
        content_length = "0"

    headers = {"Content-Length": content_length}
    if content_type is not None:
        headers["Content-Type"] = content_type
    if host is not None:
        headers["Host"] = host
    if origin is not None:
        headers["Origin"] = origin
    handler.headers = headers

    return handler


# ===================================================================
# _handle_login — validation
# ===================================================================


def test_login_empty_cookie():
    handler = _make_handler()
    handler._send_json = Mock()
    handler._handle_login({"cookie": ""})

    resp = handler._send_json.call_args[0][0]
    assert "error" in resp
    assert "cookie" in resp["error"].lower()


# ===================================================================
# _handle_login — success and failure
# ===================================================================


def test_login_success():
    handler = _make_handler()
    handler._send_json = Mock()
    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch("monarch_mcp.auth_server._run_sync"),
        patch("monarch_mcp.auth_server.secure_session") as mock_ss,
    ):
        handler._handle_login({"cookie": "session_id=a; csrftoken=b"})

    mock_ss.save_authenticated_session.assert_called_once()
    assert handler.auth_state.completed is True
    resp = handler._send_json.call_args[0][0]
    assert resp["success"] is True


def test_login_invalid_cookie():
    handler = _make_handler()
    handler._send_json = Mock()
    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch(
            "monarch_mcp.auth_server._run_sync",
            side_effect=LoginFailedException("Missing required cookies"),
        ),
    ):
        handler._handle_login({"cookie": "not=valid"})

    resp = handler._send_json.call_args[0][0]
    assert "error" in resp
    assert "Missing required cookies" in resp["error"]


# ===================================================================
# _send_json / _send_html
# ===================================================================


def test_send_json():
    handler = _make_handler()
    handler._send_json({"key": "value"})

    handler.send_response.assert_called_once_with(200)
    # Check Content-Type header
    ct_calls = [
        c for c in handler.send_header.call_args_list
        if c[0][0] == "Content-Type"
    ]
    assert ct_calls[0][0][1] == "application/json"
    written = handler.wfile.getvalue()
    assert json.loads(written) == {"key": "value"}


def test_send_html():
    handler = _make_handler()
    handler._send_html("<h1>Hello</h1>")

    handler.send_response.assert_called_once_with(200)
    ct_calls = [
        c for c in handler.send_header.call_args_list
        if c[0][0] == "Content-Type"
    ]
    assert "text/html" in ct_calls[0][0][1]
    written = handler.wfile.getvalue()
    assert b"<h1>Hello</h1>" in written


# ===================================================================
# log_message
# ===================================================================


def test_log_message():
    handler = _make_handler()
    with patch("monarch_mcp.auth_server.logger") as mock_log:
        handler.log_message("request %s %s", "GET", "/")

    mock_log.debug.assert_called_once()
    assert "GET" in mock_log.debug.call_args[0][1]


# ===================================================================
# do_GET routing
# ===================================================================


def test_do_get_root():
    handler = _make_handler(path="/")
    handler._send_html = Mock()
    handler.do_GET()

    handler._send_html.assert_called_once()
    assert "Monarch" in handler._send_html.call_args[0][0]


def test_do_get_404():
    handler = _make_handler(path="/nonexistent")
    handler.do_GET()

    handler.send_error.assert_called_once_with(404)


# ===================================================================
# do_POST routing
# ===================================================================


def test_do_post_login_route():
    handler = _make_handler(path="/login", body={"cookie": ""})
    handler._send_json = Mock()
    handler.do_POST()

    # Should reach _handle_login which validates the empty cookie field
    handler._send_json.assert_called_once()
    resp = handler._send_json.call_args[0][0]
    assert "error" in resp


def test_do_post_unknown_route():
    handler = _make_handler(path="/unknown", body={})
    handler.do_POST()

    handler.send_error.assert_called_once_with(404)


def test_do_post_invalid_json():
    handler = _make_handler(path="/login")
    handler.rfile = io.BytesIO(b"not-json{{{")
    handler.headers = {
        "Content-Length": "11",
        "Content-Type": "application/json",
        "Host": "127.0.0.1:8080",
        "Origin": "http://127.0.0.1:8080",
    }
    handler._send_json = Mock()

    handler.do_POST()

    resp = handler._send_json.call_args[0][0]
    assert "Invalid request body" in resp["error"]


# ===================================================================
# _find_free_port
# ===================================================================


def test_find_free_port():
    port = _find_free_port()
    assert isinstance(port, int)
    assert port > 0


# ===================================================================
# _validate_credential
# ===================================================================


def test_validate_credential_token_valid():
    with (
        patch("monarch_mcp.auth_server.MonarchMoney") as mock_cls,
        patch("monarch_mcp.auth_server._run_sync"),
    ):
        mock_cls.return_value = MagicMock()
        result = _validate_credential({"auth_mode": "token", "token": "good-token"})

    assert result is True
    mock_cls.assert_called_once_with(token="good-token")


def test_validate_credential_cookie_valid():
    with (
        patch("monarch_mcp.auth_server.MonarchMoney") as mock_cls,
        patch("monarch_mcp.auth_server._run_sync"),
    ):
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        cred = {"auth_mode": "cookie", "cookies": {"session_id": "a", "csrftoken": "b"}}
        result = _validate_credential(cred)

    assert result is True
    mock_client.set_cookies.assert_called_once_with({"session_id": "a", "csrftoken": "b"})


def test_validate_credential_auth_error():
    from gql.transport.exceptions import TransportServerError  # pylint: disable=import-outside-toplevel

    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch(
            "monarch_mcp.auth_server._run_sync",
            side_effect=TransportServerError("Unauthorized", code=401),
        ),
    ):
        result = _validate_credential({"auth_mode": "token", "token": "bad-token"})

    assert result is False


def test_validate_credential_server_error():
    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch(
            "monarch_mcp.auth_server._run_sync",
            side_effect=OSError("network down"),
        ),
    ):
        result = _validate_credential({"auth_mode": "token", "token": "some-token"})

    assert result is None


# ===================================================================
# Request-origin guards (CSRF / DNS-rebinding hardening)
# ===================================================================


def test_do_post_rejects_non_json_content_type():
    # A cross-site fetch can dodge a CORS preflight by sending a "simple"
    # Content-Type like text/plain. Such a request must be rejected before
    # any authentication side effect (login-CSRF).
    handler = _make_handler(
        path="/login",
        body={"cookie": "session=attacker"},
        content_type="text/plain",
    )
    handler._send_json = Mock()
    handler._handle_login = Mock()
    handler.do_POST()

    handler.send_error.assert_called_once_with(403)
    handler._handle_login.assert_not_called()


def test_do_post_rejects_cross_origin():
    handler = _make_handler(
        path="/login",
        body={"cookie": "session=attacker"},
        origin="https://evil.example",
    )
    handler._send_json = Mock()
    handler._handle_login = Mock()
    handler.do_POST()

    handler.send_error.assert_called_once_with(403)
    handler._handle_login.assert_not_called()


def test_do_post_rejects_unexpected_host():
    # DNS-rebinding: a rebound hostname that resolves to 127.0.0.1.
    handler = _make_handler(
        path="/login",
        body={"cookie": "session=attacker"},
        host="attacker.example",
    )
    handler._send_json = Mock()
    handler._handle_login = Mock()
    handler.do_POST()

    handler.send_error.assert_called_once_with(403)
    handler._handle_login.assert_not_called()


def test_do_get_rejects_unexpected_host():
    handler = _make_handler(path="/", host="attacker.example")
    handler._send_html = Mock()
    handler.do_GET()

    handler.send_error.assert_called_once_with(403)
    handler._send_html.assert_not_called()


def test_do_post_allows_request_without_origin_header():
    # Non-browser clients (which omit Origin) on the correct loopback Host
    # are still served, as long as Content-Type is application/json.
    handler = _make_handler(
        path="/login",
        body={"cookie": ""},
        origin=None,
    )
    handler._send_json = Mock()
    handler.do_POST()

    handler.send_error.assert_not_called()
    resp = handler._send_json.call_args[0][0]
    assert "error" in resp
    assert "cookie" in resp["error"].lower()


# ===================================================================
# Error-message hygiene (no internal details leaked to the client)
# ===================================================================


def test_login_unexpected_error_returns_generic_message():
    handler = _make_handler()
    handler._send_json = Mock()
    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch(
            "monarch_mcp.auth_server._run_sync",
            side_effect=RuntimeError("internal stack detail xyz"),
        ),
    ):
        handler._handle_login({"cookie": "session=abc"})

    resp = handler._send_json.call_args[0][0]
    assert "error" in resp
    assert "internal stack detail xyz" not in resp["error"]
    # Points the operator to where the real detail lives, without leaking it.
    assert "logs" in resp["error"].lower()


# ===================================================================
# Secret hygiene (pasted cookie not written to logs)
# ===================================================================


def test_login_failure_does_not_log_cookie():
    from monarchmoney import LoginFailedException  # pylint: disable=import-outside-toplevel

    handler = _make_handler()
    handler._send_json = Mock()
    with (
        patch("monarch_mcp.auth_server.MonarchMoney"),
        patch(
            "monarch_mcp.auth_server._run_sync",
            side_effect=LoginFailedException("Missing required cookies"),
        ),
        patch("monarch_mcp.auth_server.logger") as mock_log,
    ):
        handler._handle_login({"cookie": "session=SECRETCOOKIEVALUE"})

    logged = " ".join(
        str(arg)
        for call in (
            mock_log.error.call_args_list
            + mock_log.info.call_args_list
            + mock_log.warning.call_args_list
        )
        for arg in call[0]
    )
    assert "SECRETCOOKIEVALUE" not in logged
