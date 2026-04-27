# Authenticating a CLI App with Inouk API Auth

> Tutorial — How to add OAuth 2.1 authentication to a CLI tool (mpy, mgx, custom).
> Full endpoint reference: [README §OAuth 2.0 / 2.1 Authentication](../README.md#oauth-20--21-authentication).

## Why Device Code Flow?

Three OAuth flows are exposed by `inouk_api_auth`. One decision: which one suits your CLI?

| Flow | Use when | Notes |
|---|---|---|
| `authorization_code + PKCE` | CLI runs on a machine with a graphical browser. | The CLI spawns a localhost callback (`http://localhost:<port>/callback`); the browser redirects there with the code. |
| `device_code` (RFC 8628) | CLI runs in SSH, containers, headless servers, shared environments. | The CLI prints a URL, the user opens it on any device. **← this tutorial.** |
| `client_credentials` | No human (CI/CD, scheduled jobs). | M2M, server-side secret, no consent screen. |

The Device Code Flow is the right pick when the CLI cannot open a browser locally — typical for `mpy` and `mgx` running on remote dev servers.

## The flow at a glance

```
┌─────────────┐              ┌─────────────┐              ┌─────────────────┐
│   CLI       │              │  Browser    │              │  Muppy Server   │
└──────┬──────┘              └──────┬──────┘              └────────┬────────┘
       │ 0. POST /oauth/register (one-time DCR)                    │
       │──────────────────────────────────────────────────────────>│
       │ ← client_id                                               │
       │                                                           │
       │ 1. POST /oauth/device/code                                │
       │──────────────────────────────────────────────────────────>│
       │ ← { device_code, user_code, verification_uri_complete }   │
       │                                                           │
       │ 2. Display URL — "Visit: https://…/oauth/device?code=…"   │
       │                            │                              │
       │                            │ 3. Open URL → login → consent│
       │                            │─────────────────────────────>│
       │                                                           │
       │ 4. Poll POST /oauth/token (grant=device_code) every Ns    │
       │──────────────────────────────────────────────────────────>│
       │ ← { access_token, refresh_token }                         │
       │                                                           │
       │ 5. Use Authorization: Bearer ikaa_… on /api/...           │
       │ 6. (later) Refresh before expiry                          │
       │──────────────────────────────────────────────────────────>│
```

## Prerequisites

```bash
export SERVER_URL="https://your-server"
```

## Step 0 — Register your client (one-time, RFC 7591)

**What:** Declare your CLI as an OAuth client.

**Why:** The server needs to know which `client_id` to issue tokens for. Dynamic Client Registration avoids manually creating clients via the Odoo UI for every CLI distribution. The pre-registered `mpy-cli` and `mgx-cli` clients (in [`data/oauth_clients.xml`](../data/oauth_clients.xml)) skip this step for first-party tools.

```bash
curl -X POST "${SERVER_URL}/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My CLI Tool",
    "redirect_uris": ["http://localhost:8080/callback"],
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "token_endpoint_auth_method": "none"
  }'
```

**Response:**
```json
{ "client_id": "ikac_xxx", "client_id_issued_at": 1735900000, "client_secret_expires_at": 0 }
```

**Gotchas:**
- `redirect_uris` must match the server's allowlist (`inouk_api_auth.oauth_allowed_redirect_patterns` ICP — Claude.ai + localhost by default).
- `token_endpoint_auth_method: "none"` declares a **public** client (typical for CLIs — no secret to protect). Security comes from the device code itself, not from a client secret.

```bash
export CLIENT_ID="ikac_xxx"
```

## Step 1 — Request a device code

**What:** Ask the server to start a pending authorization.

**Why:** The response returns three things, each with a distinct role:
- `device_code` — long secret, **used by the CLI** to poll for the outcome. Never shown to the user.
- `user_code` — short `XXXX-XXXX` code, displayed if the user needs to enter it manually on a different device (fallback UX).
- `verification_uri_complete` — one-click URL with the code embedded. **Primary UX path.**

The `expires_in` (default 15 min) bounds how long the user has to authorize.

```bash
curl -X POST "${SERVER_URL}/oauth/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=mcp:discovery mcp:read"
```

**Response:**
```json
{
  "device_code": "dc_xxx",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://your-server/oauth/device",
  "verification_uri_complete": "https://your-server/oauth/device?code=dc_xxx",
  "expires_in": 900,
  "interval": 5
}
```

## Step 2 — Display the URL, start polling

**What:** Print `verification_uri_complete` to the user, immediately begin polling Step 4.

**Why:** The user can authorize on any device (own laptop, phone, kiosk). The CLI never touches the user's session — it just waits for the server to confirm against the `device_code` it holds.

```
To sign in, visit:
  https://your-server/oauth/device?code=dc_xxx

Waiting for authorization…
```

## Step 3 — User authorizes (browser side, automatic from CLI's POV)

**What:** The user opens the URL → server displays a consent screen → user clicks **Authorize** → server marks the `device_code` as authorized.

**Why:** This is the only step where a human is in the loop. The consent screen displays the client name and the requested scopes, so the user can refuse. From the CLI's perspective, this happens out-of-band — the CLI just polls.

## Step 4 — Poll for the token

**What:** Repeatedly POST to `/oauth/token` until the user authorizes (or denies, or the code expires).

**Why:** RFC 8628 uses polling because there is no webhook channel from server to CLI. The server returns one of:

| Status | Body | CLI action |
|---|---|---|
| `200` | `{access_token, refresh_token, …}` | **Success — store both tokens.** |
| `400` | `{"error":"authorization_pending"}` | Keep polling at the suggested interval. |
| `400` | `{"error":"slow_down"}` | Back off — increase interval by ~5 s. |
| `400` | `{"error":"access_denied"}` | User clicked Deny. Stop. |
| `400` | `{"error":"expired_token"}` | `expires_in` exceeded — start over from Step 1. |

```bash
export DEVICE_CODE="dc_xxx"
curl -X POST "${SERVER_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=${DEVICE_CODE}" \
  -d "client_id=${CLIENT_ID}"
```

**Success response:**
```json
{
  "access_token": "ikaa_xxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ikrt_xxx",
  "scope": "mcp:discovery mcp:read"
}
```

A complete Python polling loop is in [README §Device Code Flow](../README.md#device-code-flow-cli-tools).

## Step 5 — Use the access token

**What:** Send `Authorization: Bearer ikaa_xxx` on every API call.

**Why:** Standard RFC 6750. Routes use `auth='ik_bearer'` to consume the token transparently.

```bash
export TOKEN="ikaa_xxx"
curl "${SERVER_URL}/inouk/api_auth/v2/token/status/bearer" \
  -H "Authorization: Bearer ${TOKEN}"
```

## Step 6 — Refresh before expiry

**What:** Exchange the `refresh_token` for a new pair when the access token nears expiration.

**Why:** Two reasons:
- `access_token` lifetime is short (1 h default) — limits the blast radius of a leaked token.
- `refresh_token` **rotates** by default. Each refresh emits a new pair and **revokes the old refresh_token**. Reusing a revoked refresh_token returns `invalid_grant: Refresh token has been revoked`. This is intentional: it detects token theft (when both legitimate client and attacker hold the same refresh_token, only the first to use it succeeds — the second use raises an alarm).

```bash
curl -X POST "${SERVER_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=${OLD_REFRESH_TOKEN}" \
  -d "client_id=${CLIENT_ID}"
```

Returns the same shape as Step 4. **Discard the old `refresh_token` immediately** after a successful refresh.

## Reference

- [README §OAuth 2.0 / 2.1 Authentication](../README.md#oauth-20--21-authentication) — full endpoint reference, including the Authorization Code + PKCE flow and Client Credentials (M2M).
- RFC 8628 — Device Authorization Grant.
- RFC 7591 — Dynamic Client Registration.
- RFC 6749 — OAuth 2.0 core.
- RFC 6750 — Bearer Token usage.
