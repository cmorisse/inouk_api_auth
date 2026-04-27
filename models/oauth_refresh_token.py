# -*- coding: utf-8 -*-
"""OAuth 2.1 Refresh Token

This module implements refresh tokens for OAuth 2.1 Authorization Code flow.
Refresh tokens allow clients to obtain new access tokens without requiring
user interaction, enabling long-lived sessions.
"""

import secrets

from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthRefreshToken(models.Model):
    _name = 'ik.oauth_refresh_token'
    _description = "OAuth 2.1 Refresh Token"
    _order = 'create_date desc'

    # ═══════════════════════════════════════════════════════════════════════════
    # TOKEN IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    token = fields.Char(
        string="Refresh Token",
        required=True,
        index=True,
        readonly=True,
        copy=False,
        default=lambda self: self._generate_token(),
        help="256-bit random token, base64url encoded with prefix (ikrt_)"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # RELATIONSHIPS
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
        help="User who authorized the token"
    )
    access_token_id = fields.Many2one(
        'ik.api_auth_token',
        string="Current Access Token",
        ondelete='set null',
        help="Most recently issued access token"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHORIZATION CONTEXT
    # ═══════════════════════════════════════════════════════════════════════════

    scope = fields.Char(
        string="Scope",
        help="Space-separated list of granted scopes"
    )
    resource = fields.Char(
        string="Resource",
        help="RFC 8707 resource indicator"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════════

    expires_at = fields.Datetime(
        string="Expires At",
        default=lambda self: self._compute_default_expires_at(),
        help="Refresh token expiration (default: 30 days)"
    )
    revoked = fields.Boolean(
        string="Revoked",
        default=False,
        help="Token has been explicitly revoked"
    )
    revoked_at = fields.Datetime(
        string="Revoked At"
    )
    last_used_at = fields.Datetime(
        string="Last Used At",
        help="Timestamp of last token refresh"
    )
    use_count = fields.Integer(
        string="Use Count",
        default=0,
        help="Number of times this token has been used"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SQL CONSTRAINTS
    # ═══════════════════════════════════════════════════════════════════════════

    _sql_constraints = [
        ('token_unique', 'unique(token)', 'Refresh token must be unique'),
    ]

    # ═══════════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    def _compute_default_expires_at(self):
        """Compute default expiration time from system parameter."""
        lifetime_days = int(self.env['ir.config_parameter'].sudo().get_param(
            'inouk_api_auth.oauth_refresh_lifetime_days', '30'
        ))
        return fields.Datetime.add(fields.Datetime.now(), days=lifetime_days)

    @api.model
    def _generate_token(self):
        """Generate a cryptographically secure refresh token.

        Returns:
            str: Token with 'ikrt_' prefix and 256 bits of randomness
        """
        return f"ikrt_{secrets.token_urlsafe(32)}"

    def validate(self):
        """Validate refresh token is usable.

        Returns:
            self

        Raises:
            ValidationError: If token is revoked or expired
        """
        self.ensure_one()

        if self.revoked:
            raise ValidationError("Refresh token has been revoked")

        if self.expires_at and fields.Datetime.now() > self.expires_at:
            raise ValidationError("Refresh token has expired")

        # Check if client is still active
        if not self.client_registration_id.active:
            raise ValidationError("Client registration is inactive")

        return self

    def use(self):
        """Record token usage.

        Called when the token is used to obtain a new access token.

        Returns:
            self
        """
        self.ensure_one()
        self.write({
            'last_used_at': fields.Datetime.now(),
            'use_count': self.use_count + 1,
        })
        return self

    def revoke(self):
        """Revoke this refresh token and its associated access token.

        After revocation, the token cannot be used to obtain new access tokens.
        The associated access token is also invalidated.

        Returns:
            bool: True on success
        """
        self.ensure_one()
        self.write({
            'revoked': True,
            'revoked_at': fields.Datetime.now(),
        })
        # Also revoke the associated access token
        if self.access_token_id:
            self.access_token_id.write({'is_compromised': True})
        return True

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC HELPER — TOKEN PAIR ISSUANCE
    # ═══════════════════════════════════════════════════════════════════════════
    # Pure-ORM classmethod extracted from OAuthController._issue_tokens so that
    # downstream addons (e.g. inouk_mcp) can issue token pairs with their own
    # extra fields (e.g. mcp_instance_id) without depending on the HTTP layer.

    @api.model
    def issue_token_pair(self, client_registration, user, scope, resource,
                         old_refresh_token=None,
                         extra_access_vals=None, extra_refresh_vals=None):
        """Issue an access_token + refresh_token pair (RFC 6749).

        Single source of truth for OAuth 2.1 token issuance. Replaces the
        historical OAuthController._issue_tokens. The HTTP controller wraps
        this method's return value in a Response.

        Args:
            client_registration: ik.oauth_client_registration record.
            user: res.users record on whose behalf the token is issued.
            scope: str. Granted scope (space-separated).
            resource: str | None. RFC 8707 resource indicator.
            old_refresh_token: ik.oauth_refresh_token record | None. When
                refreshing, the existing refresh_token (drives rotation policy).
            extra_access_vals: dict | None. Extra fields merged into
                ``ik.api_auth_token.create()``. Used by callers that need to
                attach an audience binding (e.g. inouk_mcp passes
                ``{'mcp_instance_id': instance.id}``). Must NOT collide with
                core fields managed below.
            extra_refresh_vals: dict | None. Extra fields merged into
                ``ik.oauth_refresh_token.create()``. Same rules.

        Returns:
            dict: RFC 6749 token response payload, ready for JSON serialization::

                {
                    'access_token': str,
                    'token_type': 'Bearer',
                    'expires_in': int,
                    'refresh_token': str,
                    'scope': str,
                }

        Side effects (single transaction):
            - Creates a new ik.api_auth_token (header type, OAuth 2.1).
            - Creates or rotates a ik.oauth_refresh_token.
            - Revokes ``old_refresh_token`` if rotation is enabled.
        """
        Token = self.env['ik.api_auth_token'].sudo()
        RefreshToken = self.env['ik.oauth_refresh_token'].sudo()
        ICP = self.env['ir.config_parameter'].sudo()

        token_lifetime = int(ICP.get_param(
            'inouk_api_auth.oauth_token_lifetime', '3600'))

        # Build access token vals (core fields + caller extras)
        access_vals = {
            'name': f"OAuth2.1 token for {client_registration.client_name}",
            'user_id': user.id,
            'token_type': 'header',
            'header_name': 'Authorization',
            'header_prefix': 'Bearer ',
            'support_url_param': True,
            'url_param_name': 'access_token',
            'expiration_ts': fields.Datetime.add(
                fields.Datetime.now(), seconds=token_lifetime),
            'oauth21_client_registration_id': client_registration.id,
            'oauth21_scope': scope,
            'oauth21_resource': resource,
        }
        if extra_access_vals:
            access_vals.update(extra_access_vals)

        access_token = Token.create(access_vals)
        # Generate the static token value and save it
        access_token.static_token = access_token.generate_credentials_header()

        # Handle refresh token (rotation policy)
        rotate_refresh = ICP.get_param(
            'inouk_api_auth.oauth_rotate_refresh_tokens', 'true'
        ).lower() == 'true'

        if old_refresh_token and not rotate_refresh:
            # Reuse existing refresh token
            old_refresh_token.write({'access_token_id': access_token.id})
            old_refresh_token.use()
            refresh_token_value = old_refresh_token.token
        else:
            refresh_vals = {
                'client_registration_id': client_registration.id,
                'user_id': user.id,
                'access_token_id': access_token.id,
                'scope': scope,
                'resource': resource,
            }
            if extra_refresh_vals:
                refresh_vals.update(extra_refresh_vals)
            new_refresh = RefreshToken.create(refresh_vals)
            refresh_token_value = new_refresh.token

            # Link to access token
            access_token.write({'oauth21_refresh_token_id': new_refresh.id})

            # Revoke old refresh token if rotating
            if old_refresh_token and rotate_refresh:
                old_refresh_token.revoke()

        return {
            'access_token': access_token.static_token,
            'token_type': 'Bearer',
            'expires_in': token_lifetime,
            'refresh_token': refresh_token_value,
            'scope': scope,
        }

    @api.model
    def _cron_cleanup_expired(self):
        """Cleanup expired and revoked refresh tokens.

        Called by daily cron job to remove:
        - Expired tokens (after expiration date)
        - Revoked tokens (after 7 days for audit trail)
        """
        now = fields.Datetime.now()

        # Delete expired tokens
        expired = self.search([
            ('expires_at', '!=', False),
            ('expires_at', '<', now),
        ])

        # Delete revoked tokens after 7 days (audit trail)
        cutoff = fields.Datetime.subtract(now, days=7)
        revoked = self.search([
            ('revoked', '=', True),
            ('revoked_at', '<', cutoff),
        ])

        to_delete = expired | revoked
        if to_delete:
            to_delete.unlink()

        return True
