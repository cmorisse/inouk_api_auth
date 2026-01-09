# Testing OAuth Device Flow via CLI

This guide explains how to test the OAuth 2.0 Device Authorization Flow (RFC 8628) using curl commands.

## Prerequisites

```bash
export SERVER_URL="https://mpy18c-k8s-dev-cyril.muppy.cloud"
```

## Step 0: Register a Client (Dynamic Client Registration - RFC 7591)

Register a new OAuth client. This only needs to be done once.

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
{
  "client_id": "ikac_xxxxxxxxxxxx",
  "client_name": "My CLI Tool",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_id_issued_at": 1735900000,
  "client_secret_expires_at": 0
}
```

Save the `client_id` for subsequent steps:
```bash
export CLIENT_ID="ikac_xxxxxxxxxxxx"
```

**Note:** For public clients (CLI tools), use `"token_endpoint_auth_method": "none"`. Security is ensured via the device code mechanism.

## Step 1: Request Device Code

```bash
curl -X POST "${SERVER_URL}/oauth/device/code" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_ID}" \
  -d "scope=mcp:discovery mcp:metadata mcp:operations"
```

**Response:**
```json
{
  "device_code": "dc_GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://server/oauth/device",
  "verification_uri_complete": "https://server/oauth/device?code=dc_xxx",
  "expires_in": 900,
  "interval": 5
}
```

## Step 2: Open Consent Screen in Browser

Open `verification_uri_complete` in your browser to see the consent form.

## Step 3: Poll for Token (in another terminal)

```bash
export DEVICE_CODE="dc_xxx"  # From step 1

# Poll every 5 seconds until authorized
curl -X POST "${SERVER_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=${DEVICE_CODE}" \
  -d "client_id=${CLIENT_ID}"
```

**While waiting:** `{"error": "authorization_pending"}`

**After user authorizes:**
```json
{
  "access_token": "ikaa_xxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ikrt_xxx",
  "scope": "mcp:discovery mcp:metadata mcp:operations"
}
```

## Step 4: Test API with Token

```bash
export TOKEN="ikaa_xxx"

curl -X POST "${SERVER_URL}/mcp" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```
