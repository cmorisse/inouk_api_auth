"""
OAuth 2.0 Token Endpoint (Client Credentials Flow - SEP-1046)

This controller implements the OAuth 2.0 Client Credentials flow
for machine-to-machine authentication, enabling tools like Claude Desktop
to connect directly to MCP servers via URL.

See auth.py header for detailed documentation on route type selection.
This endpoint uses type='http' to support both:
- application/x-www-form-urlencoded (OAuth 2.0 standard - RFC 6749)
- application/json (modern clients)
"""

import json
import logging
import secrets

from odoo import http, fields
from odoo.http import request, Response

_logger = logging.getLogger(__name__)


class OAuthController(http.Controller):

    @http.route('/.well-known/oauth-authorization-server', type='http', auth='none',
                methods=['GET'], csrf=False, save_session=False)
    def oauth_discovery(self, **kwargs):
        """OAuth 2.0 Authorization Server Metadata (RFC 8414).

        Returns metadata about the OAuth server so MCP clients can discover endpoints.
        This is required by the MCP OAuth specification.
        """
        base_url = request.httprequest.host_url.rstrip('/')

        metadata = {
            'issuer': base_url,
            'token_endpoint': f'{base_url}/oauth/token',
            'token_endpoint_auth_methods_supported': ['client_secret_post'],
            'grant_types_supported': ['client_credentials'],
            'response_types_supported': ['token'],
            'scopes_supported': ['mcp'],
        }

        _logger.info(f"═══ OAUTH DISCOVERY REQUEST ═══")
        _logger.info(f"  From: {request.httprequest.remote_addr}")
        _logger.info(f"  User-Agent: {request.httprequest.headers.get('User-Agent', 'None')}")
        _logger.info(f"═══ OAUTH DISCOVERY RESPONSE ═══")
        _logger.info(f"  Status: 200")
        _logger.info(f"  Body: {json.dumps(metadata)}")

        return Response(
            json.dumps(metadata),
            content_type='application/json',
            status=200
        )

    @http.route('/oauth/token', type='http', auth='none', methods=['POST'], csrf=False, save_session=False)
    def oauth_token(self, **kwargs):
        """OAuth 2.0 Token Endpoint (Client Credentials Flow - SEP-1046)

        Supports both content types:
        - application/x-www-form-urlencoded (OAuth 2.0 standard - RFC 6749)
        - application/json (modern clients like Claude Desktop)

        Request parameters:
        - grant_type: must be "client_credentials"
        - client_id: OAuth client identifier (ikaa_xxx format)
        - client_secret: OAuth client secret

        Response (200 OK):
        {
            "access_token": "ikaa_...",
            "token_type": "Bearer",
            "expires_in": 3600
        }
        """
        # Detailed logging for debugging
        content_type = request.httprequest.content_type or ''
        _logger.info(f"═══ OAUTH TOKEN REQUEST ═══")
        _logger.info(f"  From: {request.httprequest.remote_addr}")
        _logger.info(f"  Content-Type: {content_type}")
        _logger.info(f"  User-Agent: {request.httprequest.headers.get('User-Agent', 'None')}")

        # Dual-format support: form-urlencoded OR JSON
        if 'application/json' in content_type:
            # JSON body (modern clients)
            try:
                data = json.loads(request.httprequest.get_data(as_text=True))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                return self._oauth_error('invalid_request', 'Invalid JSON: {}'.format(e))
            grant_type = data.get('grant_type')
            client_id = data.get('client_id')
            client_secret = data.get('client_secret')
        else:
            # Form-urlencoded (standard OAuth 2.0/2.1)
            grant_type = kwargs.get('grant_type')
            client_id = kwargs.get('client_id')
            client_secret = kwargs.get('client_secret')

        _logger.info(f"  Grant Type: {grant_type}")
        _logger.info(f"  Client ID: {client_id}")
        _logger.info(f"  Client Secret: {'***' if client_secret else 'None'}")

        # Validation
        if grant_type != 'client_credentials':
            return self._oauth_error('unsupported_grant_type',
                'Only client_credentials grant type is supported')

        if not client_id or not client_secret:
            return self._oauth_error('invalid_request',
                'client_id and client_secret are required')

        # Lookup OAuth client
        client = request.env['ik.api_auth_token'].sudo().search([
            ('oauth_client_id', '=', client_id),
            ('token_type', '=', 'oauth_client'),
        ], limit=1)

        if not client:
            _logger.warning("OAuth: Unknown client_id: %s", client_id)
            return self._oauth_error('invalid_client', 'Unknown client_id')

        # Validate client_secret (constant-time comparison to prevent timing attacks)
        if not secrets.compare_digest(client.oauth_client_secret or '', client_secret or ''):
            _logger.warning("OAuth: Invalid credentials for client_id: %s", client_id)
            return self._oauth_error('invalid_client', 'Invalid credentials')

        # Check client status
        if client.is_compromised:
            _logger.warning("OAuth: Compromised client attempted access: %s", client_id)
            return self._oauth_error('invalid_client', 'Client is disabled')

        if client.expiration_ts and client.expiration_ts <= fields.Datetime.now():
            return self._oauth_error('invalid_client', 'Client credentials expired')

        # Generate new Bearer token
        bearer_token = client.generate_access_token()
        expires_in = client.oauth_token_lifetime or 3600

        token_response = {
            'access_token': bearer_token.static_token,
            'token_type': 'Bearer',
            'expires_in': expires_in,
        }
        _logger.info(f"═══ OAUTH TOKEN RESPONSE ═══")
        _logger.info(f"  Status: 200")
        _logger.info(f"  Client: {client.name}")
        _logger.info(f"  Token: {bearer_token.static_token[:20]}...")
        _logger.info(f"  Expires In: {expires_in}s")

        return Response(
            json.dumps(token_response),
            content_type='application/json',
            status=200
        )

    def _oauth_error(self, error, description=None):
        """Return OAuth 2.0 error response (RFC 6749).

        Error codes:
        - invalid_request: Missing or invalid parameters (400)
        - invalid_client: Unknown client or bad credentials (401)
        - unsupported_grant_type: Grant type not supported (400)
        """
        body = {'error': error}
        if description:
            body['error_description'] = description

        # Status codes per RFC 6749
        status = 400  # invalid_request, unsupported_grant_type
        if error == 'invalid_client':
            status = 401

        _logger.info(f"═══ OAUTH TOKEN ERROR RESPONSE ═══")
        _logger.info(f"  Status: {status}")
        _logger.info(f"  Error: {error}")
        _logger.info(f"  Description: {description}")

        return Response(
            json.dumps(body),
            content_type='application/json',
            status=status
        )
