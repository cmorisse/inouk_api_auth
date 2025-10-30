# -*- coding: utf-8 -*-
import logging

from odoo import models, fields
from odoo.http import request, AuthenticationError

_logger = logging.getLogger(__name__)


class IrHttpBearer(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_ik_bearer(cls):
        """Authentication method for Bearer Token and X-Gitlab-Token

        This method implements Bearer Token authentication as defined in RFC 6750
        https://tools.ietf.org/html/rfc6750

        The token can be passed using:
        - Authorization header: "Authorization: Bearer <token>"
        - X-Gitlab-Token header: "X-Gitlab-Token: <token>"
        - access_token URL parameter: "?access_token=<token>"
        """
        # Get request information for security checks
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')

        # Try to extract token from various sources
        token_string = None
        token_type = None

        # Check Authorization header first (standard Bearer token)
        auth_header = request.httprequest.headers.get('Authorization')
        if auth_header:
            token_string = auth_header
            token_type = 'bearer'
            _logger.info("Received header 'Authorization: %s'", token_string)

        # Check X-Gitlab-Token header (GitLab webhook compatibility)
        if not token_string:
            gitlab_token = request.httprequest.headers.get('X-Gitlab-Token')
            if gitlab_token:
                token_string = gitlab_token
                token_type = 'xgitlabtoken'
                _logger.info("Received header 'X-Gitlab-Token: %s'", token_string)

        # Check URL parameter as last resort
        if not token_string:
            token_string = request.params.get('access_token')
            if not token_string:
                token_string = request.httprequest.args.get('access_token')

            if token_string:
                # Remove from params to avoid passing it to the controller
                if 'access_token' in request.params:
                    del request.params['access_token']
                token_type = 'bearer'
            else:
                raise AuthenticationError("Missing required Authorization.")

        # Extract the actual token value
        if token_string.lower().startswith('bearer '):
            static_token = token_string.split()[1]
        else:
            static_token = token_string.strip()

        # Search for token in database (single search, no validity filters)
        # Bearer and X-Gitlab-Token are unified - search for both types
        # Include 'header' type for backward compatibility
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('static_token', '=', static_token),
            ('token_type', 'in', ['bearer', 'xgitlabtoken', 'header']),
        ], order='id DESC', limit=1)

        # Decision tree based on token status
        if not token_obj:
            _logger.warning("Bearer authentication failed - no token found for static token")
            raise AuthenticationError("Invalid Access Token.")
        elif token_obj.is_compromised:
            _logger.warning("Bearer authentication failed - token %s (ID: %s) is compromised",
                          token_obj.name, token_obj.id)
            raise AuthenticationError("Invalid Access Token.")
        elif token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("Bearer authentication failed - token %s (ID: %s) expired at %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts)
            raise AuthenticationError("Invalid Access Token.")

        # Check if token was sent over HTTPS
        is_compromised = cls._check_token_compromised(request, http_referer)

        if is_compromised:
            if token_obj.enforce_integrity:
                # Mark token as compromised and expire it
                cls._compromise_token(token_obj, sender_ip)
                raise AuthenticationError("Invalid Access Token.")
            else:
                _logger.warning("Token %s received over unsecure 'http' from %s.", token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.session.uid = user_obj.id
        request.uid = user_obj.id

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Build auth details specific to Bearer/X-Gitlab-Token
        auth_details = {
            'header_type': 'Authorization' if auth_header else 'X-Gitlab-Token',
            'token_source': 'header' if token_string != request.params.get('access_token', '') else 'url_param'
        }

        # Build and store complete auth context
        request.inouk_api_auth = cls._build_auth_context(
            token_obj=token_obj,
            auth_type=token_type,
            auth_details=auth_details
        )

        # Keep legacy attribute for backward compatibility
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via token %s", user_obj.name, token_obj.name)