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

This module enables seamless integration between Odoo and external tools while maintaining security and auditability.