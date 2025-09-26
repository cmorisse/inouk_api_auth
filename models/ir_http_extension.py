# -*- coding: utf-8 -*-
import logging
from urllib.parse import urlparse

from odoo import models, fields
from odoo.http import request, AuthenticationError

_logger = logging.getLogger(__name__)


class IrHttpExtension(models.AbstractModel):
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

        # Search for valid token in database
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('static_token', '=', static_token),
            ('token_type', '=', token_type),
            ('is_compromised', '=', False),
            '|',
                ('expiration_ts', '=', False),
                ('expiration_ts', '>', fields.Datetime.now()),
        ], order='id DESC', limit=1)

        if not token_obj:
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

        # Store token object for access in controller
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via token %s", user_obj.name, token_obj.name)

    @classmethod
    def _check_token_compromised(cls, req, http_referer):
        """Check if the token transmission was compromised (not sent over HTTPS)

        Args:
            req: The current request object
            http_referer: The HTTP referer header value

        Returns:
            bool: True if the connection is compromised (not HTTPS), False if secure
        """
        requested_url = req.httprequest.url
        parsed_url = urlparse(requested_url)

        # Check if current request is not HTTPS
        if parsed_url.scheme != 'https':
            _logger.debug("Request URL is not HTTPS: %s", requested_url)
            return True

        # Check if referer is present and not HTTPS
        if http_referer:
            parsed_referer = urlparse(http_referer)
            if parsed_referer.scheme != 'https':
                _logger.debug("HTTP_REFERER is not HTTPS: %s", http_referer)
                return True

        return False

    @classmethod
    def _compromise_token(cls, token_obj, sender_ip):
        """Mark a token as compromised due to security violation

        Args:
            token_obj: The token record to mark as compromised
            sender_ip: The IP address that sent the compromised token
        """
        timestamp = fields.Datetime.now().isoformat()
        security_message = (
            f"{timestamp}: Token expired by Muppy since it has been received over "
            f"'http' from {sender_ip}.\n{token_obj.security_log or ''}"
        )

        token_obj.write({
            'is_compromised': True,
            'expiration_ts': fields.Datetime.now(),
            'security_log': security_message
        })

        # Force commit to ensure the token is immediately marked as compromised
        token_obj.flush()
        request.env.cr.commit()

        _logger.info("Token %s (ID: %s) set as compromised!", token_obj.name, token_obj.id)