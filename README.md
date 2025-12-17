# Inouk API Auth

Token-based API authentication system with plain JSON support for Odoo.

## Features

- **Multiple authentication methods**: Bearer tokens, AWS Signature V4, HTTP Basic Auth
- **Plain JSON support**: Bypass Odoo's JSON-RPC for external REST clients
- **HTTPS integrity enforcement**: Automatic token compromise detection
- **Token lifecycle management**: Expiration, compromise detection, and security logging
- **Comprehensive request analysis**: Real IP detection, proxy chain analysis

## Authentication Methods

### Bearer Token (`auth='ik_bearer'`)
Standard Bearer token authentication supporting:
- `Authorization: Bearer <token>` header
- `X-Gitlab-Token: <token>` header (GitLab webhook compatibility)
- `?access_token=<token>` URL parameter (fallback)

### AWS Signature V4 (`auth='ik_awssigv4'`)
Full AWS SigV4 implementation for AWS CLI/SDK compatibility:
- Credential-based authentication with access key and secret
- Request signing validation with timestamp and region
- Compatible with AWS tools and libraries

### HTTP Basic Auth (`auth='ik_httpbasicauth'`)
RFC 7617 compliant Basic authentication:
- `Authorization: Basic <base64(username:password)>` header
- Secure password hashing with verification
- Username-based token lookup

## Plain JSON Support

### Why This Feature Exists

External REST clients (LEGO, Terraform, curl, etc.) expect standard JSON APIs:
- **Send**: `{"key": "value"}`
- **Receive**: `{"result": "data"}`

Odoo's `type='json'` routes expect JSON-RPC protocol with wrapper:
- **Expected**: `{"jsonrpc": "2.0", "method": "call", "params": {...}, "id": 1}`
- **Returns**: `{"jsonrpc": "2.0", "result": {...}, "id": 1}`

This incompatibility prevents integration with external tools.

### Usage

Add `ik_plain_json=True` to any JSON route:

```python
from odoo import http

class MyController(http.Controller):

    @http.route('/api/endpoint', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, ik_plain_json=True)
    def my_api(self, **params):
        # params contains the raw JSON body
        return {"status": "success", "data": params}
```

**Client usage:**
```bash
curl -X POST https://example.com/api/endpoint \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

**Response:**
```json
{"status": "success", "data": {"key": "value"}}
```

### Implementation Details

The module patches `JsonRequest` to detect `ik_plain_json` routes and:

1. **Parameter handling**: Use raw JSON body as controller params (no JSON-RPC parsing)
2. **Response formatting**: Return plain JSON responses (no JSON-RPC wrapper)
3. **Error handling**: Standard JSON error responses with appropriate HTTP status codes

**Error response format:**
```json
{"error": "Error message", "status": "error"}
```

### Managing HTTP Status Codes

With `ik_plain_json=True`, you can control HTTP response status codes by raising exceptions.

#### Using Werkzeug HTTPException (Recommended)

```python
from werkzeug.exceptions import BadRequest, NotFound, Forbidden, Conflict

@http.route('/api/resource', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def create_resource(self, name, **params):
    if not name:
        raise BadRequest("Name is required")  # Returns HTTP 400

    existing = self.env['my.model'].search([('name', '=', name)])
    if existing:
        raise Conflict("Resource already exists")  # Returns HTTP 409

    return {'status': 'success', 'id': new_record.id}
```

#### Common HTTPException Classes

| Exception | HTTP Status | Use Case |
|-----------|-------------|----------|
| `BadRequest` | 400 | Invalid input, missing required fields |
| `Unauthorized` | 401 | Authentication failed |
| `Forbidden` | 403 | Insufficient permissions |
| `NotFound` | 404 | Resource not found |
| `Conflict` | 409 | Resource already exists, version conflict |
| `UnprocessableEntity` | 422 | Validation errors |
| `InternalServerError` | 500 | Unexpected server errors |

#### Using Custom Exceptions with status_code

For custom status codes, create an exception class with a `status_code` attribute:

```python
class QuotaExceeded(Exception):
    status_code = 429

    def __init__(self, message="Quota exceeded"):
        self.name = message
        super().__init__(message)

@http.route('/api/resource', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def create_resource(self, **params):
    if self._quota_exceeded():
        raise QuotaExceeded("Daily quota exceeded, try again tomorrow")
    # ... rest of logic
```

#### Status Code Resolution Order

| Exception Type | Status Code Source |
|----------------|-------------------|
| `werkzeug.exceptions.HTTPException` | `e.code` |
| Exception with `status_code` attribute | `e.status_code` |
| Any other exception | `500` (default) |

### Why Monkey Patching is Necessary

**Technical constraints:**
- Odoo's request factory instantiates `JsonRequest` internally based on `Content-Type` headers
- External clients cannot be modified to send custom headers
- No exposed factory method to override request class instantiation

**Alternative approaches considered:**
- **Classic inheritance**: Cannot replace Odoo's internal request factory
- **Middleware**: Would require WSGI stack modifications
- **Decorator pattern**: Cannot intercept request parsing early enough

**Our solution** is the least invasive approach that maintains full Odoo compatibility while enabling external tool integration.

## Token Management

### Security Features

- **HTTPS enforcement**: Tokens sent over HTTP are automatically compromised
- **Real IP detection**: Supports Cloudflare and other proxy configurations
- **Compromise detection**: Automatic token invalidation on security violations
- **Audit logging**: Complete request tracing with IP and proxy information

### Token Types

Tokens support different authentication backends:
- `bearer`: Standard Bearer tokens
- `xgitlabtoken`: GitLab webhook tokens
- `awssigv4`: AWS access key credentials
- `httpbasicauth`: HTTP Basic Auth credentials

### Request Context

All authentication methods populate `request.inouk_api_auth` with:

```python
{
    'token': token_object,
    'token_name': 'Token Name',
    'token_type': 'bearer|awssigv4|httpbasicauth',
    'user': user_object,
    'is_compromised': False,
    'is_expired': False,
    'authenticated_at': '2025-01-01T12:00:00',
    'auth_details': {
        # Method-specific authentication details
    },
    'request_source': {
        'remote_ip': '1.2.3.4',  # Real client IP
        'via': '5.6.7.8',        # Proxy IP (if behind proxy)
        'proxy_chain': ['5.6.7.8'],
        'proxy_type': 'cloudflare|nginx|generic',
        'using_https': True,
        'user_agent': 'curl/8.0.0',
        'referer': 'https://example.com'
    }
}
```

## Integration Examples

### ACME DNS Challenge (LEGO)
```python
@http.route('/dns/challenge', type='json', auth='ik_httpbasicauth',
            methods=['POST'], csrf=False, ik_plain_json=True)
def dns_challenge(self, domain, token, **params):
    # LEGO sends: {"domain": "example.com", "token": "challenge_token"}
    return {"message": "Challenge added successfully"}
```

### Webhook Endpoints
```python
@http.route('/webhooks/deploy', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def deploy_webhook(self, repository, commit, **params):
    # GitHub/GitLab webhook payload directly available in params
    return {"status": "deployment_started"}
```

### Infrastructure APIs
```python
@http.route('/infra/provision', type='json', auth='ik_awssigv4',
            methods=['POST'], csrf=False, ik_plain_json=True)
def provision_infrastructure(self, **params):
    # AWS CLI/SDK compatible endpoint
    return {"instance_id": "i-1234567890abcdef0"}
```

## Testing Plain JSON Support

### Running Automated Tests

Run the full test suite for `inouk_api_auth`:
```bash
bin/start_odoo --test-enable --stop-after-init -u inouk_api_auth
```

Run only the plain JSON tests (using test tag):
```bash
bin/start_odoo --test-enable --stop-after-init -u inouk_api_auth --test-tags=plain_json
```

### Test Endpoints

The module includes test endpoints for validating `ik_plain_json` functionality:

| Endpoint | Purpose |
|----------|---------|
| `/inouk/api_auth/test/plain_json/echo` | Echo params - validates request/response |
| `/inouk/api_auth/test/plain_json/error_400` | Test BadRequest (HTTP 400) |
| `/inouk/api_auth/test/plain_json/error_403` | Test Forbidden (HTTP 403) |
| `/inouk/api_auth/test/plain_json/error_404` | Test NotFound (HTTP 404) |
| `/inouk/api_auth/test/plain_json/error_custom` | Test custom status_code (HTTP 422) |
| `/inouk/api_auth/test/plain_json/error_500` | Test generic exception (HTTP 500) |
| `/inouk/api_auth/test/plain_json/datetime` | Test datetime serialization |
| `/inouk/api_auth/test/plain_json/response_object` | Test Response pass-through |

### Manual Testing with curl

1. **Create a test token** in Odoo (Settings > Technical > API Auth Tokens)

2. **Test basic echo endpoint:**
```bash
curl -X POST https://your-server/inouk/api_auth/test/plain_json/echo \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello", "count": 42}'
```

**Expected response** (plain JSON, no JSON-RPC wrapper):
```json
{"status": "success", "echo": {"message": "hello", "count": 42}}
```

3. **Test error handling (400 Bad Request):**
```bash
curl -i -X POST https://your-server/inouk/api_auth/test/plain_json/error_400 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 400 with plain JSON error:
```json
{"error": "400 Bad Request: Test bad request error", "status": "error"}
```

4. **Test custom status code (422):**
```bash
curl -i -X POST https://your-server/inouk/api_auth/test/plain_json/error_custom \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 422 with plain JSON error:
```json
{"error": "Test custom status code error", "status": "error"}
```

5. **Test datetime serialization:**
```bash
curl -X POST https://your-server/inouk/api_auth/test/plain_json/datetime \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** ISO-formatted datetime strings:
```json
{"datetime": "2025-01-15T10:30:00", "date": "2025-01-15", "string": "test", "number": 42}
```

### Validation Checklist

When testing `ik_plain_json` support, verify:

- [ ] Successful responses return plain JSON (no `jsonrpc`, `id`, `result` wrapper keys)
- [ ] Error responses return plain JSON with `{"error": "...", "status": "error"}` format
- [ ] HTTPException classes return correct HTTP status codes (400, 403, 404, etc.)
- [ ] Custom exceptions with `status_code` attribute return that status code
- [ ] Generic exceptions return HTTP 500
- [ ] Datetime objects are serialized to ISO format strings
- [ ] Response objects from endpoints are passed through unchanged
- [ ] Content-Type header is `application/json`

This module enables seamless integration between Odoo and external tools while maintaining security and auditability.