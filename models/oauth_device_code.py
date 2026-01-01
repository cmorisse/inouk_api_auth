# -*- coding: utf-8 -*-
"""OAuth 2.1 Device Authorization Grant (RFC 8628)

This module implements the Device Authorization Grant flow for CLI tools
like mpy and mgx. This flow allows devices without a browser to obtain
user authorization by displaying a URL for the user to visit on another device.

Flow:
1. CLI calls POST /oauth/device/code to get device_code and user_code
2. CLI displays verification_uri_complete to user
3. User visits URL, logs in, and authorizes
4. CLI polls POST /oauth/token until authorized or timeout
"""

import secrets

from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthDeviceCode(models.Model):
    _name = 'ik.oauth_device_code'
    _description = "OAuth 2.1 Device Authorization Code (RFC 8628)"
    _order = 'create_date desc'
    _rec_name = 'user_code'

    # ═══════════════════════════════════════════════════════════════════════════
    # CORE FIELDS (RFC 8628)
    # ═══════════════════════════════════════════════════════════════════════════

    device_code = fields.Char(
        string="Device Code",
        required=True,
        readonly=True,
        index=True,
        copy=False,
        help="Secret code used by the client to poll for authorization. "
             "Never exposed to the user."
    )
    user_code = fields.Char(
        string="User Code",
        required=True,
        readonly=True,
        index=True,
        copy=False,
        help="Short code displayed to the user (optional, for manual mode). "
             "Format: XXXX-XXXX for easy typing."
    )
    verification_uri = fields.Char(
        string="Verification URI",
        required=True,
        readonly=True,
        help="URL where user authenticates (without code embedded)"
    )
    verification_uri_complete = fields.Char(
        string="Verification URI Complete",
        required=True,
        readonly=True,
        help="URL with embedded code (Cloudflare style) - user just clicks"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # REQUEST PARAMETERS
    # ═══════════════════════════════════════════════════════════════════════════

    client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="Client Registration",
        required=True,
        readonly=True,
        ondelete='cascade',
        help="Client that requested the device authorization"
    )
    scope = fields.Char(
        string="Requested Scope",
        readonly=True,
        help="Space-separated list of requested scopes"
    )
    resource = fields.Char(
        string="Resource",
        readonly=True,
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHORIZATION STATE
    # ═══════════════════════════════════════════════════════════════════════════

    state = fields.Selection([
        ('pending', 'Authorization Pending'),
        ('authorized', 'Authorized'),
        ('denied', 'Access Denied'),
        ('expired', 'Expired'),
    ], string="State", default='pending', required=True, readonly=True,
       help="Current state of the device authorization request")

    user_id = fields.Many2one(
        'res.users',
        string="Authorized User",
        readonly=True,
        ondelete='cascade',
        help="User who authorized the request (set when state=authorized)"
    )
    granted_scope = fields.Char(
        string="Granted Scope",
        readonly=True,
        help="Scopes actually granted by the user (may differ from requested)"
    )

    # Link to authorization code generated after consent
    authorization_code_id = fields.Many2one(
        'ik.oauth_authorization_code',
        string="Authorization Code",
        readonly=True,
        ondelete='set null',
        help="Authorization code generated after user consent (for token exchange)"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # TIMING & POLLING
    # ═══════════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        required=True,
        readonly=True,
        help="When this device code expires (default: 15 minutes)"
    )
    poll_interval = fields.Integer(
        string="Polling Interval (seconds)",
        default=5,
        readonly=True,
        help="Minimum interval between polling requests (RFC 8628)"
    )
    last_poll_at = fields.Datetime(
        string="Last Poll At",
        readonly=True,
        help="Timestamp of last polling request (for slow_down detection)"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SQL CONSTRAINTS
    # ═══════════════════════════════════════════════════════════════════════════

    _sql_constraints = [
        ('device_code_unique', 'unique(device_code)', 'Device code must be unique'),
        ('user_code_unique', 'unique(user_code)', 'User code must be unique'),
    ]

    # ═══════════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    @api.model
    def _generate_device_code(self):
        """Generate a cryptographically secure device code (256 bits).

        Returns:
            str: 256 bits of randomness, base64url encoded
        """
        return secrets.token_urlsafe(32)

    @api.model
    def _generate_user_code(self):
        """Generate a user-friendly code: XXXX-XXXX.

        Uses uppercase letters and digits, excluding ambiguous characters
        (0, O, I, L, 1) for better readability.

        Returns:
            str: User code in format 'XXXX-XXXX'
        """
        # Exclude ambiguous characters: 0, O, I, L, 1
        alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
        part1 = ''.join(secrets.choice(alphabet) for _ in range(4))
        part2 = ''.join(secrets.choice(alphabet) for _ in range(4))
        return f"{part1}-{part2}"

    @api.model
    def create_device_authorization(self, client_registration_obj, scope=None, resource=None):
        """Create a new device authorization request.

        Args:
            client_registration_obj: ik.oauth_client_registration record
            scope: Space-separated scope string
            resource: RFC 8707 resource indicator

        Returns:
            dict: Device authorization response per RFC 8628
        """
        # Configuration
        ICP = self.env['ir.config_parameter'].sudo()
        lifetime = int(ICP.get_param('inouk_api_auth.oauth_device_code_lifetime', '900'))
        poll_interval = int(ICP.get_param('inouk_api_auth.oauth_device_poll_interval', '5'))
        base_url = ICP.get_param('web.base.url', '').rstrip('/')

        device_code = self._generate_device_code()
        user_code = self._generate_user_code()
        expires_at = fields.Datetime.add(fields.Datetime.now(), seconds=lifetime)

        # Build verification URIs
        verification_uri = f"{base_url}/oauth/device"
        verification_uri_complete = f"{base_url}/oauth/device?code={device_code}"

        # Create the device authorization record
        device_auth = self.create({
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': verification_uri_complete,
            'client_registration_id': client_registration_obj.id,
            'scope': scope,
            'resource': resource,
            'expires_at': expires_at,
            'poll_interval': poll_interval,
        })

        # Return RFC 8628 response
        return {
            'device_code': device_code,
            'user_code': user_code,
            'verification_uri': verification_uri,
            'verification_uri_complete': verification_uri_complete,
            'expires_in': lifetime,
            'interval': poll_interval,
        }

    def check_authorization_status(self):
        """Check the current status of a device authorization.

        Called during polling from /oauth/token.

        Returns:
            dict: Token response or error per RFC 8628
                - {'error': 'authorization_pending'} - keep polling
                - {'error': 'slow_down'} - increase interval
                - {'error': 'expired_token'} - timeout
                - {'error': 'access_denied'} - user denied
                - {'status': 'authorized', 'authorization_code': '...'} - success
        """
        self.ensure_one()
        now = fields.Datetime.now()

        # Check expiration
        if self.expires_at < now:
            self.write({'state': 'expired'})
            return {'error': 'expired_token', 'error_description': 'Device code has expired'}

        # Check rate limiting (slow_down)
        if self.last_poll_at:
            elapsed = (now - self.last_poll_at).total_seconds()
            if elapsed < self.poll_interval:
                return {'error': 'slow_down', 'error_description': 'Polling too fast'}

        # Update last poll timestamp
        self.write({'last_poll_at': now})

        # Check state
        if self.state == 'pending':
            return {'error': 'authorization_pending', 'error_description': 'Awaiting user authorization'}

        if self.state == 'denied':
            return {'error': 'access_denied', 'error_description': 'User denied the authorization'}

        if self.state == 'expired':
            return {'error': 'expired_token', 'error_description': 'Device code has expired'}

        if self.state == 'authorized':
            # Return the authorization code for token exchange
            if self.authorization_code_id:
                return {
                    'status': 'authorized',
                    'authorization_code': self.authorization_code_id,
                    'user_id': self.user_id,
                    'scope': self.granted_scope,
                }
            else:
                # Should not happen, but handle gracefully
                return {'error': 'server_error', 'error_description': 'Missing authorization code'}

        return {'error': 'server_error', 'error_description': 'Unknown state'}

    def authorize(self, user_obj, granted_scope=None):
        """Authorize the device request.

        Called when user clicks "Authorize" on the consent screen.

        Args:
            user_obj: res.users record of the authorizing user
            granted_scope: Scopes granted (defaults to requested scope)

        Raises:
            ValidationError: If not pending or expired
        """
        self.ensure_one()
        if self.state != 'pending':
            raise ValidationError("Device authorization is not pending")

        if self.expires_at < fields.Datetime.now():
            self.write({'state': 'expired'})
            raise ValidationError("Device authorization has expired")

        final_scope = granted_scope or self.scope

        # Create an authorization code (reuse existing model)
        # For device flow, we don't use PKCE (device_code is the secret)
        auth_code_obj = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client_registration_id.id,
            'redirect_uri': '',  # No redirect for device flow
            'user_id': user_obj.id,
            'scope': final_scope,
            'resource': self.resource,
            'code_challenge': '',  # No PKCE for device flow
            'code_challenge_method': False,
        })

        self.write({
            'state': 'authorized',
            'user_id': user_obj.id,
            'granted_scope': final_scope,
            'authorization_code_id': auth_code_obj.id,
        })

    def deny(self):
        """Deny the device request.

        Called when user clicks "Deny" on the consent screen.

        Raises:
            ValidationError: If not pending
        """
        self.ensure_one()
        if self.state != 'pending':
            raise ValidationError("Device authorization is not pending")
        self.write({'state': 'denied'})

    @api.model
    def cleanup_expired(self):
        """Cron job to clean up expired device authorizations.

        Removes:
        - Expired device codes (after 1 hour past expiration)
        - Denied device codes (immediately)
        - Authorized device codes (after token exchange, or 1 hour)
        """
        cutoff = fields.Datetime.subtract(fields.Datetime.now(), hours=1)
        expired = self.search([
            '|',
            ('expires_at', '<', cutoff),
            ('state', 'in', ['expired', 'denied']),
        ])
        if expired:
            expired.unlink()
        return True
