"""SecureMonarchSession unit tests.

Covers save/load/delete credential (token and cookie modes),
get_authenticated_client, save_authenticated_session, and
_cleanup_old_session_files.
"""
# pylint: disable=missing-function-docstring,protected-access

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from monarch_mcp.secure_session import SecureMonarchSession


@pytest.fixture
def session():
    """Fresh SecureMonarchSession instance for each test."""
    return SecureMonarchSession()


# ===================================================================
# save_token / save_cookies
# ===================================================================


def test_save_token_success(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        session._cleanup_old_session_files = MagicMock()
        session.save_token("tok-123")

    args = mock_kr.set_password.call_args[0]
    assert args[0] == "com.mcp.monarch-mcp"
    assert args[1] == "monarch-token"
    assert json.loads(args[2]) == {"auth_mode": "token", "token": "tok-123"}
    session._cleanup_old_session_files.assert_called_once()


def test_save_token_keyring_failure(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.set_password.side_effect = RuntimeError("keyring locked")
        with pytest.raises(RuntimeError, match="keyring locked"):
            session.save_token("tok-123")


def test_save_cookies_success(session):
    cookies = {"session_id": "abc", "csrftoken": "def"}
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        session._cleanup_old_session_files = MagicMock()
        session.save_cookies(cookies)

    args = mock_kr.set_password.call_args[0]
    assert json.loads(args[2]) == {"auth_mode": "cookie", "cookies": cookies}
    session._cleanup_old_session_files.assert_called_once()


# ===================================================================
# load_credential
# ===================================================================


def test_load_credential_cookie(session):
    stored = json.dumps({"auth_mode": "cookie", "cookies": {"session_id": "a", "csrftoken": "b"}})
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.return_value = stored
        result = session.load_credential()

    assert result == {"auth_mode": "cookie", "cookies": {"session_id": "a", "csrftoken": "b"}}


def test_load_credential_token_json(session):
    stored = json.dumps({"auth_mode": "token", "token": "tok-abc"})
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.return_value = stored
        result = session.load_credential()

    assert result == {"auth_mode": "token", "token": "tok-abc"}


def test_load_credential_legacy_plain_token(session):
    """A bare string from before cookie-auth support is treated as a legacy token."""
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.return_value = "tok-abc"
        result = session.load_credential()

    assert result == {"auth_mode": "token", "token": "tok-abc"}


def test_load_credential_not_found(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.return_value = None
        result = session.load_credential()

    assert result is None


def test_load_credential_exception(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.side_effect = RuntimeError("backend crash")
        result = session.load_credential()

    assert result is None


# ===================================================================
# delete_token
# ===================================================================


def test_delete_token_success(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        session._cleanup_old_session_files = MagicMock()
        session.delete_token()

    mock_kr.delete_password.assert_called_once()
    session._cleanup_old_session_files.assert_called_once()


def test_delete_token_not_found(session):
    import keyring.errors  # pylint: disable=import-outside-toplevel

    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.errors = keyring.errors
        mock_kr.delete_password.side_effect = keyring.errors.PasswordDeleteError()
        session.delete_token()  # should not raise


def test_delete_token_generic_exception(session):
    import keyring.errors  # pylint: disable=import-outside-toplevel

    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.errors = keyring.errors
        mock_kr.delete_password.side_effect = OSError("disk full")
        session.delete_token()  # should not raise


# ===================================================================
# get_authenticated_client
# ===================================================================


def test_get_client_success_token(session):
    with (
        patch("monarch_mcp.secure_session.keyring") as mock_kr,
        patch("monarch_mcp.secure_session.MonarchMoney") as mock_cls,
    ):
        mock_kr.get_password.return_value = "tok-abc"
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        result = session.get_authenticated_client()

    assert result is mock_client
    mock_cls.assert_called_once_with(token="tok-abc")


def test_get_client_success_cookie(session):
    stored = json.dumps({"auth_mode": "cookie", "cookies": {"session_id": "a", "csrftoken": "b"}})
    with (
        patch("monarch_mcp.secure_session.keyring") as mock_kr,
        patch("monarch_mcp.secure_session.MonarchMoney") as mock_cls,
    ):
        mock_kr.get_password.return_value = stored
        mock_client = MagicMock()
        mock_cls.return_value = mock_client

        result = session.get_authenticated_client()

    assert result is mock_client
    mock_cls.assert_called_once_with()
    mock_client.set_cookies.assert_called_once_with({"session_id": "a", "csrftoken": "b"})


def test_get_client_no_credential(session):
    with patch("monarch_mcp.secure_session.keyring") as mock_kr:
        mock_kr.get_password.return_value = None
        result = session.get_authenticated_client()

    assert result is None


def test_get_client_creation_exception(session):
    with (
        patch("monarch_mcp.secure_session.keyring") as mock_kr,
        patch("monarch_mcp.secure_session.MonarchMoney") as mock_cls,
    ):
        mock_kr.get_password.return_value = "tok-abc"
        mock_cls.side_effect = RuntimeError("constructor failed")

        result = session.get_authenticated_client()

    assert result is None


# ===================================================================
# save_authenticated_session
# ===================================================================


def test_save_session_with_cookies(session):
    mm = MagicMock()
    mm._cookies = {"session_id": "a", "csrftoken": "b"}
    session.save_cookies = MagicMock()
    session.save_token = MagicMock()

    session.save_authenticated_session(mm)

    session.save_cookies.assert_called_once_with({"session_id": "a", "csrftoken": "b"})
    session.save_token.assert_not_called()


def test_save_session_with_token(session):
    mm = MagicMock()
    mm._cookies = None
    mm.token = "tok-xyz"
    session.save_token = MagicMock()

    session.save_authenticated_session(mm)

    session.save_token.assert_called_once_with("tok-xyz")


def test_save_session_no_credential(session):
    mm = MagicMock()
    mm._cookies = None
    mm.token = None
    session.save_token = MagicMock()

    session.save_authenticated_session(mm)

    session.save_token.assert_not_called()


# ===================================================================
# _cleanup_old_session_files
# ===================================================================


def test_cleanup_removes_file(session, tmp_path, monkeypatch):
    target = tmp_path / "monarch_session.json"
    target.write_text("{}")
    monkeypatch.chdir(tmp_path)

    session._cleanup_old_session_files()

    assert not target.exists()


def test_cleanup_removes_empty_dir(session, tmp_path, monkeypatch):
    mm_dir = tmp_path / ".mm"
    mm_dir.mkdir()
    monkeypatch.chdir(tmp_path)

    session._cleanup_old_session_files()

    assert not mm_dir.exists()


def test_cleanup_skips_nonexistent(session, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # No files exist — should complete without error
    session._cleanup_old_session_files()


def test_cleanup_handles_exception(session, tmp_path, monkeypatch):
    target = tmp_path / "monarch_session.json"
    target.write_text("{}")
    monkeypatch.chdir(tmp_path)

    with patch("monarch_mcp.secure_session.os.remove",
               side_effect=PermissionError("read-only")):
        session._cleanup_old_session_files()  # should not raise

    # File still exists because removal failed
    assert target.exists()
