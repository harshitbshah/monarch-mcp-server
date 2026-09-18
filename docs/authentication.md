# Authentication Architecture

Technical details on how the Monarch MCP Server handles authentication, session management, and security.

## Why cookies, not password/MFA

Monarch put a Cloudflare CAPTCHA challenge in front of `/auth/login/` as an
anti-bot measure, which blocks all programmatic sign-in — password-only,
password+MFA, doesn't matter. There's no library-level workaround: this is a
deliberate platform policy, not a bug (see
[bradleyseanf/monarchmoneycommunity#40](https://github.com/bradleyseanf/monarchmoneycommunity/issues/40)).
The accepted fix, upstream and here, is to reuse a session cookie from a real,
already-authenticated browser tab instead of trying to defeat the CAPTCHA.

## Authentication Flow

1. On startup the server checks for a credential in the system keyring
2. If none is found (or it's expired), a local HTTP server is started on a
   random port and the browser is opened to a login page
3. The user signs into `app.monarch.com` in a normal tab, copies the `Cookie`
   header from a GraphQL request in DevTools, and pastes it into the login page
4. `MonarchMoney.login_with_cookies()` parses and verifies the cookie
   (`session_id` + `csrftoken` required) with a live `get_accounts()` call
5. On success the credential is saved to the keyring and the temporary auth
   server shuts down automatically
6. If the credential later expires, the same flow is re-triggered on the next
   tool call

## Session Management

- Credentials are stored securely in the system keyring (service: `com.mcp.monarch-mcp`) as a small JSON envelope: `{"auth_mode": "cookie", "cookies": {...}}`
- A bare (non-JSON) string already in the keyring from before cookie-auth support is treated as a legacy bearer token (`{"auth_mode": "token", ...}`) and still works via `MonarchMoney(token=...)`
- Monarch's own session lifetime is unchanged — cookie-based sessions still last weeks to months, same as the old bearer tokens
- Sessions persist across Claude Desktop restarts
- Expired credentials are detected automatically (401/403 from a live API call) and cleared, triggering re-authentication

## Security

- Credentials are entered in your local browser, never transmitted through Claude Desktop
- The auth server binds to `127.0.0.1` only (not accessible from the network)
- Credential stored in the OS keyring, not in plain-text files

## Fallback: CLI Login

For headless environments where a browser is not available, run:

```bash
python login_setup.py
```

This prompts for a pasted cookie string in the terminal and stores the credential in the same keyring location.
