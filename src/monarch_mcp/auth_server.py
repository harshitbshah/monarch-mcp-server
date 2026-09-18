"""
Local HTTP server for browser-based Monarch Money authentication.

When the MCP server starts and no authentication token is found,
this module spins up a temporary local web server, opens the user's
browser to a login page, and saves the resulting token to the system
keyring once the user authenticates.
"""

import asyncio
from dataclasses import dataclass
import json
import logging
import os
import socket
import threading
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

from gql.transport.exceptions import TransportServerError
from monarchmoney import MonarchMoney, LoginFailedException

from monarch_mcp.secure_session import secure_session, is_auth_error

logger = logging.getLogger(__name__)

# Maximum time (seconds) the auth server will stay alive waiting for login
_AUTH_TIMEOUT = 600  # 10 minutes

# Guard: prevent multiple auth servers from running simultaneously
_auth_lock = threading.Lock()
_auth_guard: dict[str, bool] = {"active": False}

# Generic client-facing messages for unexpected errors. The real exception is
# written to the server log (stderr) only; we deliberately do not echo it to the
# browser (CWE-209), but we point the operator to where the detail lives.
_LOGIN_ERROR_MESSAGE = (
    "Login failed due to an unexpected error. "
    "Please try again, or check the server logs for details."
)

# ── HTML served to the browser ──────────────────────────────────────────

_LOGIN_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Monarch Money - Sign In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:#f5f5f5;display:flex;justify-content:center;align-items:center;
min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);
padding:40px;width:460px;max-width:92vw}
h1{color:#1a1a2e;font-size:22px;margin-bottom:6px}
.sub{color:#666;font-size:14px;margin-bottom:20px}
ol{color:#444;font-size:13px;line-height:1.7;margin:0 0 20px 18px}
ol code{background:#f0f2f5;padding:1px 5px;border-radius:4px;font-size:12px}
.fg{margin-bottom:16px}
label{display:block;color:#333;font-size:14px;font-weight:500;margin-bottom:5px}
textarea{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:8px;
font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;outline:none;
transition:border-color .2s;resize:vertical;min-height:90px}
textarea:focus{border-color:#4a90d9}
button{width:100%;padding:12px;background:#4a90d9;color:#fff;border:none;
border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;
transition:background .2s}
button:hover{background:#357abd}
button:disabled{background:#bbb;cursor:not-allowed}
.err{color:#e74c3c;font-size:13px;margin-top:12px;display:none}
.ok{text-align:center}
.ok h2{color:#27ae60;margin-bottom:10px}
.ok p{color:#666}
#done{display:none}
.sp{display:inline-block;width:15px;height:15px;border:2px solid #fff;
border-top-color:transparent;border-radius:50%;animation:r .7s linear infinite;
margin-right:8px;vertical-align:middle}
@keyframes r{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">

  <div id="login">
    <h1>Monarch Money</h1>
    <p class="sub">Connect your MCP server using a browser session cookie</p>
    <ol>
      <li>Sign in at <code>app.monarch.com</code> in a normal browser tab</li>
      <li>Open DevTools &rarr; Network tab, click any <code>graphql</code> request</li>
      <li>Under Request Headers, copy the full <code>Cookie</code> value</li>
      <li>Paste it below</li>
    </ol>
    <div class="fg">
      <label for="cookie">Cookie header</label>
      <textarea id="cookie" placeholder="session_id=...; csrftoken=..." autofocus></textarea>
    </div>
    <button id="lbtn" onclick="doLogin()">Connect</button>
    <div id="lerr" class="err"></div>
  </div>

  <div id="done" class="ok">
    <h2>Authentication Successful</h2>
    <p>Your MCP server is now connected to Monarch Money.</p>
    <p style="margin-top:10px;font-size:13px;color:#999">You can close this tab.</p>
  </div>

</div>
<script>
function show(id){
  ['login','done'].forEach(s=>document.getElementById(s).style.display='none');
  document.getElementById(id).style.display='block';
}
function showErr(id,msg){const e=document.getElementById(id);e.textContent=msg;e.style.display='block'}
function hideErr(id){document.getElementById(id).style.display='none'}

async function doLogin(){
  const cookie=document.getElementById('cookie').value.trim();
  if(!cookie){showErr('lerr','Paste your browser cookie string first.');return}
  const btn=document.getElementById('lbtn');
  btn.disabled=true;btn.innerHTML='<span class="sp"></span>Connecting\u2026';
  hideErr('lerr');
  try{
    const r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({cookie:cookie})});
    const d=await r.json();
    if(d.success){show('done')}
    else if(d.error){showErr('lerr',d.error)}
  }catch(e){showErr('lerr','Connection error. Please try again.')}
  btn.disabled=false;btn.innerHTML='Connect';
}
</script>
</body>
</html>
"""


# ── Helpers ─────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run_sync(coro):
    """Run an async coroutine synchronously in a one-shot event loop."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def with_auth_recovery(coro):
    """Await a Monarch coroutine, auto-recovering from expired auth.

    Runs in the caller's event loop (typically the FastMCP server's main
    loop) so aiohttp/gql connection pooling works correctly across calls.

    On HTTP 401/403 or ``LoginFailedException`` recognized by
    :func:`is_auth_error`, the stale keyring token is deleted, the
    browser-based login flow is re-triggered, and a ``RuntimeError`` is
    raised so the calling tool can inform the user.

    Non-auth exceptions propagate unchanged.
    """
    try:
        return await coro
    except (TransportServerError, LoginFailedException) as exc:
        if is_auth_error(exc):
            logger.warning("Token appears expired — clearing and triggering re-auth")
            secure_session.delete_token()
            trigger_auth_flow()
            raise RuntimeError(
                "Your session has expired. A login page has been opened in "
                "your browser — please sign in and try again."
            ) from exc
        raise


# ── Request handler ─────────────────────────────────────────────────────

@dataclass
class _AuthState:
    """Mutable state shared between handler and server loop."""
    completed: bool = False


class _AuthHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves the login page and processes auth requests."""

    # Attached by the factory before the server starts
    auth_state: _AuthState
    expected_port: int

    # ── Request guards (CSRF / DNS-rebinding hardening) ──

    def _allowed_hosts(self) -> set[str]:
        """Host header values that correspond to this loopback server."""
        return {
            f"127.0.0.1:{self.expected_port}",
            f"localhost:{self.expected_port}",
        }

    def _allowed_origins(self) -> set[str]:
        """Origin header values permitted to call the auth endpoints."""
        return {
            f"http://127.0.0.1:{self.expected_port}",
            f"http://localhost:{self.expected_port}",
        }

    def _is_trusted_request(self) -> bool:
        """Reject DNS-rebinding (foreign Host) and cross-origin requests.

        This server only ever talks to a same-origin page it served itself
        on ``http://127.0.0.1:<port>``.  Enforcing the Host header blocks
        DNS-rebinding attacks; enforcing the Origin header (when present)
        blocks cross-site requests.
        """
        host = self.headers.get("Host", "")
        if host not in self._allowed_hosts():
            logger.warning("Rejected request with unexpected Host header: %r", host)
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self._allowed_origins():
            logger.warning("Rejected cross-origin request (Origin: %r)", origin)
            return False
        return True

    # ── GET ──

    def do_GET(self):  # pylint: disable=invalid-name
        """Serve the login page for GET /."""
        if not self._is_trusted_request():
            self.send_error(403)
            return
        if self.path == "/":
            self._send_html(_LOGIN_PAGE)
        else:
            self.send_error(404)

    # ── POST ──

    def do_POST(self):  # pylint: disable=invalid-name
        """Handle POST requests for /login."""
        if not self._is_trusted_request():
            self.send_error(403)
            return

        # Require an application/json body.  A cross-site fetch can only set
        # this Content-Type by triggering a CORS preflight, which this server
        # (sending no Access-Control-* headers) will fail — closing the
        # login-CSRF vector that CORS-"simple" content types would leave open.
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            logger.warning("Rejected POST with non-JSON Content-Type: %r", content_type)
            self.send_error(403)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self._send_json({"error": "Invalid request body"})
            return

        if self.path == "/login":
            self._handle_login(data)
        else:
            self.send_error(404)

    # ── Auth logic ──

    def _handle_login(self, data: dict):
        """Authenticate using a pasted browser cookie string.

        Monarch now blocks programmatic password/MFA login behind a
        Cloudflare CAPTCHA, so the only working path is a session
        cookie copied from an already-authenticated browser tab.
        """
        cookie_string = data.get("cookie", "").strip()

        if not cookie_string:
            self._send_json({"error": "Paste your browser cookie string first."})
            return

        try:
            mm = MonarchMoney()
            _run_sync(mm.login_with_cookies(cookie_string, save_session=False))

            secure_session.save_authenticated_session(mm)
            self.auth_state.completed = True
            logger.info("Browser authentication successful (cookie)")
            self._send_json({"success": True})

        except LoginFailedException as exc:
            logger.error("Cookie login failed: %s", exc)
            self._send_json(
                {"error": str(exc) or "Invalid cookie. Please copy a fresh one and try again."}
            )

        except TransportServerError as exc:
            code = getattr(exc, "code", "unknown")
            logger.error("Monarch API HTTP %s during cookie login: %s", code, exc)
            self._send_json(
                {"error": f"Monarch API error (HTTP {code}). Please try again later."}
            )

        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Unexpected error during cookie login: %s", exc)
            self._send_json({"error": _LOGIN_ERROR_MESSAGE})

    # ── Response helpers ──

    def _send_json(self, obj: dict):
        """Send a JSON response with 200 status."""
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html: str):
        """Send an HTML response with 200 status."""
        payload = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Redirect default stderr logging to our logger."""
        logger.debug("Auth server: %s", format % args)


# ── Public API ──────────────────────────────────────────────────────────

def _validate_credential(cred: dict) -> bool | None:
    """Check whether a stored credential (cookie or token) is still valid.

    Returns True if it works, False if it's definitively invalid
    (401/403), or None if validation was inconclusive due to a
    server-side error (so the existing credential should be kept).
    """
    try:
        if cred["auth_mode"] == "cookie":
            mm = MonarchMoney()
            mm.set_cookies(cred["cookies"])
        else:
            mm = MonarchMoney(token=cred["token"])
        _run_sync(mm.get_accounts())
        return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if is_auth_error(exc):
            logger.warning("Stored credential is invalid or expired: %s", exc)
            return False
        # Server-side error (5xx, network, etc.) — don't discard the credential
        logger.warning("Could not validate credential (server error): %s", exc)
        return None


def trigger_auth_flow() -> None:
    """Check for existing credentials; if absent, open a browser login page.

    This is non-blocking: a daemon thread runs the temporary HTTP server
    while the MCP server continues its normal startup.  The auth server
    shuts itself down once the user completes login or after a timeout.

    Safe to call multiple times — only one auth server will run at a time.
    """
    with _auth_lock:
        if _auth_guard["active"]:
            logger.info("Auth server already running — skipping")
            return

        # Check keyring credential — validate it's still usable
        cred = secure_session.load_credential()
        if cred:
            result = _validate_credential(cred)
            if result is True:
                logger.info("Auth credential found and validated — skipping browser auth")
                return
            if result is None:
                # Server error — keep the credential, skip browser auth
                logger.info("Credential validation inconclusive (server error) — keeping it")
                return
            # Credential is definitively invalid (401/403) — clear it
            logger.warning("Clearing stale credential from keyring")
            secure_session.delete_token()

        # Environment-variable credentials present (handled at tool-call time)
        if os.getenv("MONARCH_EMAIL") and os.getenv("MONARCH_PASSWORD"):
            logger.info("Environment credentials found — skipping browser auth")
            return

        _auth_guard["active"] = True

    # Spin up the auth server (outside the lock — no need to hold it)
    port = _find_free_port()
    state = _AuthState()

    # Create a handler class that carries our state and expected port
    handler_class = type(
        "_BoundAuthHandler",
        (_AuthHandler,),
        {"auth_state": state, "expected_port": port},
    )

    server = HTTPServer(("127.0.0.1", port), handler_class)
    server.timeout = 1  # unblock handle_request() every second to check state

    def _serve():
        start = time.time()
        logger.info("Auth server listening on http://127.0.0.1:%d", port)
        try:
            while not state.completed:
                server.handle_request()
                if time.time() - start > _AUTH_TIMEOUT:
                    logger.warning(
                        "Auth server timed out after %d seconds — shutting down",
                        _AUTH_TIMEOUT,
                    )
                    break
            server.server_close()
            if state.completed:
                logger.info("Auth server stopped — authentication complete")
        finally:
            with _auth_lock:
                _auth_guard["active"] = False

    thread = threading.Thread(target=_serve, daemon=True, name="monarch-auth-server")
    thread.start()

    url = f"http://127.0.0.1:{port}"
    logger.info("Opening browser for Monarch Money login: %s", url)
    try:
        webbrowser.open(url)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Could not open browser automatically. "
            "Please visit %s to authenticate.",
            url,
        )
