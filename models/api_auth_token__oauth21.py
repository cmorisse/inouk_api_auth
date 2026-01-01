# -*- coding: utf-8 -*-
"""OAuth 2.1 Authorization Code flow token fields.

This module extends ik.api_auth_token with fields for tokens generated via
the OAuth 2.1 Authorization Code flow (with PKCE). These tokens are linked
to client registrations and refresh tokens.

Tokens generated via OAuth 2.1 Authorization Code flow have:
- oauth21_client_registration_id: Link to the client that obtained the token
- oauth21_refresh_token_id: Link to the associated refresh token
- oauth21_scope: Granted scopes
- oauth21_resource: RFC 8707 resource indicator

This is separate from the existing OAuth 2.0 Client Credentials flow
which uses oauth_client_id/oauth_client_secret for M2M authentication.
"""

from odoo import models, fields, api


class InoukAPIAuthTokenOAuth21(models.Model):
    _inherit = 'ik.api_auth_token'

    # ═══════════════════════════════════════════════════════════════════════════
    # OAUTH 2.1 AUTHORIZATION CODE FLOW
    # ═══════════════════════════════════════════════════════════════════════════

    oauth21_client_registration_id = fields.Many2one(
        'ik.oauth_client_registration',
        string="OAuth 2.1 Client",
        ondelete='set null',
        index=True,
        help="Client registration that issued this token (authorization_code flow). "
             "Note: This is different from oauth_parent_client_id which is for "
             "client_credentials flow tokens."
    )
    oauth21_refresh_token_id = fields.Many2one(
        'ik.oauth_refresh_token',
        string="Refresh Token",
        ondelete='set null',
        help="Associated refresh token for this access token"
    )
    oauth21_scope = fields.Char(
        string="OAuth 2.1 Scope",
        help="Space-separated list of granted scopes (e.g., 'mcp:discovery mcp:metadata')"
    )
    oauth21_resource = fields.Char(
        string="OAuth 2.1 Resource",
        help="RFC 8707 resource indicator (e.g., 'https://muppy.cloud/mcp')"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # COMPUTED FIELDS
    # ═══════════════════════════════════════════════════════════════════════════

    is_oauth21_token = fields.Boolean(
        string="Is OAuth 2.1 Token",
        compute='_compute_is_oauth21_token',
        store=True,
        help="True if this token was issued via OAuth 2.1 Authorization Code flow"
    )

    @api.depends('oauth21_client_registration_id')
    def _compute_is_oauth21_token(self):
        for record in self:
            record.is_oauth21_token = bool(record.oauth21_client_registration_id)

    # ═══════════════════════════════════════════════════════════════════════════
    # SCOPE VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    def has_scope(self, required_scope):
        """Check if token has the required scope.

        Args:
            required_scope: A single scope string (e.g., 'mcp:operations')

        Returns:
            bool: True if the token has the scope, or if scope checking
                  should be bypassed (non-OAuth 2.1 tokens).
        """
        self.ensure_one()

        # Non-OAuth 2.1 tokens bypass scope check (backward compatibility)
        if not self.is_oauth21_token:
            return True

        # Check if required scope is in granted scopes
        granted_scopes = set((self.oauth21_scope or '').split())
        return required_scope in granted_scopes

    def has_any_scope(self, scopes):
        """Check if token has at least one of the required scopes.

        Args:
            scopes: List of scope strings

        Returns:
            bool: True if token has at least one scope
        """
        self.ensure_one()

        if not self.is_oauth21_token:
            return True

        granted_scopes = set((self.oauth21_scope or '').split())
        required_scopes = set(scopes)
        return bool(granted_scopes & required_scopes)

    def has_all_scopes(self, scopes):
        """Check if token has all the required scopes.

        Args:
            scopes: List of scope strings

        Returns:
            bool: True if token has all scopes
        """
        self.ensure_one()

        if not self.is_oauth21_token:
            return True

        granted_scopes = set((self.oauth21_scope or '').split())
        required_scopes = set(scopes)
        return required_scopes.issubset(granted_scopes)
