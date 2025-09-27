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

        # Search for token in database (single search, no validity filters)
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('static_token', '=', static_token),
            ('token_type', '=', token_type),
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

        # Store token object for access in controller
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via token %s", user_obj.name, token_obj.name)

    @classmethod
    def _auth_method_ik_awssigv4(cls):
        """Authentication method for AWS Signature Version 4

        This method implements AWS Signature Version 4 authentication as defined in:
        https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

        The signature must be provided in the Authorization header with AWS4-HMAC-SHA256 algorithm.
        """
        # Get request information
        method = request.httprequest.method
        url = request.httprequest.url
        headers = dict(request.httprequest.headers)
        body = request.httprequest.get_data()

        _logger.info("AWS SigV4 auth - Method: %s, URL: %s", method, url)
        _logger.info("AWS SigV4 auth - Headers: %s", headers)

        # Check for required headers
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('AWS4-HMAC-SHA256'):
            raise AuthenticationError("Missing or invalid AWS4-HMAC-SHA256 Authorization header.")

        # Extract access key ID from Authorization header
        # Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=...
        try:
            credential_part = auth_header.split('Credential=')[1].split(',')[0]
            access_key_id = credential_part.split('/')[0]
            _logger.info("AWS SigV4 auth - Extracted access key ID: %s", access_key_id)
            _logger.info("AWS SigV4 auth - Credential part: %s", credential_part)
        except (IndexError, AttributeError):
            raise AuthenticationError("Invalid Authorization header format.")

        # Find token in database by access key ID (single search, no validity filters)
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('awssigv4_access_key_id', '=', access_key_id),
            ('token_type', '=', 'awssigv4'),
        ], order='id DESC', limit=1)

        # Decision tree based on token status
        if not token_obj:
            _logger.warning("AWS SigV4 authentication failed - no token found for Access Key: %s", access_key_id)
            raise AuthenticationError("Invalid AWS Access Key ID.")
        elif token_obj.is_compromised:
            _logger.warning("AWS SigV4 authentication failed - token %s (ID: %s) is compromised. Access Key: %s",
                          token_obj.name, token_obj.id, access_key_id)
            raise AuthenticationError("Invalid AWS Access Key ID.")
        elif token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("AWS SigV4 authentication failed - token %s (ID: %s) expired at %s. Access Key: %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts, access_key_id)
            raise AuthenticationError("Invalid AWS Access Key ID.")

        _logger.info("AWS SigV4 auth - Found token: %s", token_obj.name)

        # Extract region and service from Authorization header
        try:
            credential_parts = credential_part.split('/')
            region = credential_parts[2]
            service = credential_parts[3]
            _logger.info("AWS SigV4 auth - Extracted region: %s, service: %s", region, service)
        except IndexError:
            raise AuthenticationError("Invalid credential format in Authorization header.")

        # Validate signature (enable debug logging in development)
        # TODO: Make this configurable via settings
        debug_logging = False  # Set to True for debugging signature issues
        is_valid = cls._validate_awssigv4_signature(
            headers=headers,
            method=method,
            url=url,
            body=body,
            access_key_id=access_key_id,
            secret_access_key=token_obj.awssigv4_secret_access_key,
            region=region,
            service=service,
            debug_logging=debug_logging
        )

        if not is_valid:
            raise AuthenticationError("Invalid AWS Signature.")

        # Check if token was sent over HTTPS
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')
        is_compromised = cls._check_token_compromised(request, http_referer)

        if is_compromised:
            if token_obj.enforce_integrity:
                cls._compromise_token(token_obj, sender_ip)
                raise AuthenticationError("Invalid Access Token.")
            else:
                _logger.warning("AWS SigV4 token %s received over unsecure 'http' from %s.", token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.session.uid = user_obj.id
        request.uid = user_obj.id

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Store token object for access in controller
        request.inouk_token_obj = token_obj

        # Store region and service for access in controller
        request.awssigv4_region = region
        request.awssigv4_service = service

        _logger.debug("User %s authenticated via AWS SigV4 token %s", user_obj.name, token_obj.name)

    @classmethod
    def _validate_awssigv4_signature(cls, headers, method, url, body, access_key_id, secret_access_key, region, service, debug_logging=False):
        """Validate AWS SigV4 signature using botocore

        Args:
            headers (dict): Request headers
            method (str): HTTP method
            url (str): Request URL
            body (bytes): Request body
            access_key_id (str): AWS access key ID
            secret_access_key (str): AWS secret access key
            region (str): AWS region
            service (str): AWS service name
            debug_logging (bool): Enable detailed debug logging

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            from .awssigv4_helper import validate_aws_signature
            return validate_aws_signature(
                headers=headers,
                method=method,
                url=url,
                body=body,
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                region=region,
                service=service,
                debug_logging=debug_logging
            )
        except Exception as e:
            _logger.warning("AWS SigV4 signature validation failed: %s", e)
            return False

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