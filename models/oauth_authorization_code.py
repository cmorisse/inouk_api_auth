# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Code (RFC 6749, OAuth 2.1)

This module implements authorization codes for the OAuth 2.1 Authorization Code
flow with PKCE. Authorization codes are short-lived, single-use tokens that are
exchanged for access tokens.
"""

import secrets
import hashlib
import base64

from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthAuthorizationCode(models.Model):
    _name = 'ik.oauth_authorization_code'
    _description = "OAuth 2.1 Authorization Code"
    _order = 'create_date desc'

    # ═══════════════════════════════════════════════════════════════════════════
    # CODE IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    code = fields.Char(
        string="Authorization Code",
        required=True,
        index=True,
        readonly=True,
        copy=False,
        default=lambda self: self._generate_code(),
        help="256-bit random code, base64url encoded"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # CLIENT & USER
    # ═══════════════════════════════════════════════════════════════════════════

    client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="Client",
        required=True,
        ondelete='cascade',
        index=True
    )
    client_id = fields.Char(
        related='client_registration_id.client_id',
        store=True,
        index=True,
        string="Client ID"
    )
    user_id = fields.Many2one(
        'res.users',
        string="User",
        required=True,
        ondelete='cascade',
        index=True,
        help="User who granted consent"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHORIZATION PARAMETERS
    # ═══════════════════════════════════════════════════════════════════════════

    redirect_uri = fields.Char(
        string="Redirect URI",
        help="Callback URI for this authorization (empty for device flow)"
    )
    scope = fields.Char(
        string="Scope",
        help="Space-separated list of granted scopes"
    )
    state = fields.Char(
        string="State",
        help="CSRF protection state parameter"
    )
    resource = fields.Char(
        string="Resource",
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # PKCE (RFC 7636)
    # ═══════════════════════════════════════════════════════════════════════════

    code_challenge = fields.Char(
        string="Code Challenge",
        help="PKCE code challenge (S256 hash of verifier). "
             "Empty for device flow which uses device_code as secret."
    )
    code_challenge_method = fields.Selection([
        ('S256', 'SHA-256'),
    ], string="Code Challenge Method",
       default='S256',
       help="Only S256 is supported (plain is insecure and not allowed)"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        required=True,
        default=lambda self: self._compute_default_expires_at(),
        help="Authorization codes expire after 10 minutes max (configurable)"
    )
    used = fields.Boolean(
        string="Used",
        default=False,
        help="Code can only be used once"
    )
    used_at = fields.Datetime(
        string="Used At"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SQL CONSTRAINTS
    # ═══════════════════════════════════════════════════════════════════════════

    _sql_constraints = [
        ('code_unique', 'unique(code)', 'Authorization code must be unique'),
    ]

    # ═══════════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _compute_default_expires_at(self):
        """Compute default expiration time from system parameter."""
        lifetime = int(self.env['ir.config_parameter'].sudo().get_param(
            'inouk_api_auth.oauth_code_lifetime', '600'
        ))
        return fields.Datetime.add(fields.Datetime.now(), seconds=lifetime)

    @api.model
    def _generate_code(self):
        """Generate a cryptographically secure authorization code.

        Returns:
            str: 256 bits of randomness, base64url encoded (43 chars)
        """
        return secrets.token_urlsafe(32)

    def validate_pkce(self, code_verifier):
        """Validate PKCE code_verifier against stored code_challenge.

        Implements S256 challenge method per RFC 7636:
        code_challenge = BASE64URL(SHA256(code_verifier))

        Args:
            code_verifier: The original verifier from the client (43-128 chars)

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If PKCE validation fails
        """
        self.ensure_one()

        # Device flow doesn't use PKCE (device_code is the secret)
        if not self.code_challenge:
            return True

        if self.code_challenge_method != 'S256':
            raise ValidationError("Only S256 code challenge method is supported")

        # Validate verifier length (RFC 7636: 43-128 characters)
        if not code_verifier or len(code_verifier) < 43 or len(code_verifier) > 128:
            raise ValidationError(
                "code_verifier must be between 43 and 128 characters"
            )

        # Compute S256: BASE64URL(SHA256(code_verifier))
        verifier_bytes = code_verifier.encode('ascii')
        digest = hashlib.sha256(verifier_bytes).digest()
        computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

        # Constant-time comparison (prevent timing attacks)
        if not secrets.compare_digest(computed_challenge, self.code_challenge):
            raise ValidationError("Invalid PKCE code_verifier")

        return True

    def consume(self):
        """Mark code as used. Can only be called once.

        Per OAuth 2.1: Authorization codes MUST be single-use and
        MUST expire shortly after issuance.

        Returns:
            self

        Raises:
            ValidationError: If code was already used or is expired
        """
        self.ensure_one()

        if self.used:
            raise ValidationError("Authorization code has already been used")

        if fields.Datetime.now() > self.expires_at:
            raise ValidationError("Authorization code has expired")

        self.write({
            'used': True,
            'used_at': fields.Datetime.now(),
        })
        return self

    @api.model
    def _cron_cleanup_expired(self):
        """Cleanup expired and used authorization codes.

        Called by cron job to remove:
        - Expired codes (even if unused)
        - Used codes (after a short grace period for audit)
        """
        # Delete expired codes immediately
        expired = self.search([
            ('expires_at', '<', fields.Datetime.now()),
        ])

        # Delete used codes after 1 hour (for audit trail)
        cutoff = fields.Datetime.subtract(fields.Datetime.now(), hours=1)
        used = self.search([
            ('used', '=', True),
            ('used_at', '<', cutoff),
        ])

        to_delete = expired | used
        if to_delete:
            to_delete.unlink()

        return True
