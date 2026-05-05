# -*- coding: utf-8 -*-
"""OAuth 2.1 Client Registration (RFC 7591)

This module implements OAuth 2.1 client registration, supporting both
dynamic client registration (DCR) and manual registration for clients
like Claude.ai, CLI tools (mpy, mgx), and future mobile apps.
"""

import secrets
import fnmatch
from urllib.parse import urlparse

from odoo import models, fields, api
from odoo.exceptions import ValidationError


class IkOAuthClientRegistration(models.Model):
    _name = 'ik.oauth_client_registration'
    _description = "OAuth 2.1 Client Registration"
    _order = 'create_date desc'
    _rec_name = 'client_name'

    # ═══════════════════════════════════════════════════════════════════════════
    # CLIENT IDENTIFICATION
    # ═══════════════════════════════════════════════════════════════════════════

    client_id = fields.Char(
        string="Client ID",
        required=True,
        index=True,
        readonly=True,
        copy=False,
        default=lambda self: self._generate_client_id(),
        help="Public client identifier (prefix: ikac_)"
    )
    client_secret = fields.Char(
        string="Client Secret",
        copy=False,
        help="Client secret (optional for public clients). Prefix: ikacs_"
    )
    client_name = fields.Char(
        string="Client Name",
        required=True,
        help="Human-readable client name (e.g., 'Claude', 'mpy CLI')"
    )
    client_uri = fields.Char(
        string="Client URI",
        help="URL of the client's home page"
    )
    logo_uri = fields.Char(
        string="Logo URI",
        help="URL of the client's logo for consent screen"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # REGISTRATION TYPE & STATE
    # ═══════════════════════════════════════════════════════════════════════════

    registration_type = fields.Selection([
        ('dynamic', 'Dynamic (DCR)'),
        ('manual', 'Manual'),
    ], string="Registration Type",
       default='manual',
       required=True,
       help="How this client was registered"
    )
    active = fields.Boolean(
        string="Active",
        default=True,
        help="Inactive clients cannot obtain new tokens"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # REDIRECT URIS
    # ═══════════════════════════════════════════════════════════════════════════

    redirect_uris = fields.Text(
        string="Redirect URIs",
        help="Newline-separated list of allowed redirect URIs. "
             "HTTPS required except for localhost (CLI tools)."
    )

    @api.depends('redirect_uris')
    def _compute_redirect_uri_list(self):
        for record in self:
            if record.redirect_uris:
                uris = [u.strip() for u in record.redirect_uris.split('\n') if u.strip()]
                record.redirect_uri_list = ', '.join(uris)
            else:
                record.redirect_uri_list = ''

    redirect_uri_list = fields.Char(
        string="Redirect URI List",
        compute='_compute_redirect_uri_list',
        help="Comma-separated list for display"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # GRANT TYPES & RESPONSE TYPES
    # ═══════════════════════════════════════════════════════════════════════════

    grant_types = fields.Char(
        string="Grant Types",
        default='authorization_code,refresh_token',
        required=True,
        help="Space or comma-separated list of allowed grant types. "
             "Options: authorization_code, refresh_token, client_credentials, "
             "urn:ietf:params:oauth:grant-type:device_code"
    )
    response_types = fields.Selection([
        ('code', 'Code'),
    ], string="Response Types",
       default='code',
       required=True,
       help="OAuth response type (only 'code' supported for OAuth 2.1)"
    )
    token_endpoint_auth_method = fields.Selection([
        ('none', 'None (Public Client)'),
        ('client_secret_post', 'Client Secret POST'),
        ('client_secret_basic', 'Client Secret Basic'),
    ], string="Token Endpoint Auth Method",
       default='none',
       required=True,
       help="How the client authenticates at the token endpoint. "
            "'none' for public clients like CLI tools."
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SENSITIVE DATA ACCESS
    # ═══════════════════════════════════════════════════════════════════════════

    allow_sensitive_data = fields.Boolean(
        string="Allow Sensitive Data",
        default=False,
        help="If True, password_fields are returned in clear for MCP read operations. "
             "Auto-set for mgx-* clients at client creation."
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # SCOPES
    # ═══════════════════════════════════════════════════════════════════════════

    allowed_scopes = fields.Char(
        string="Allowed Scopes",
        default='',
        help="Space-separated list of scopes this client can request. "
             "Decoupled from MCP-specific vocabulary: it's up to the consuming "
             "addon (inouk_mcp) to scope it via its own DCR endpoint."
    )
    default_scopes = fields.Char(
        string="Default Scopes",
        default='',
        help="Scopes granted if none are requested. Empty by default — "
             "consuming addons set their own default vocabulary."
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # LIFECYCLE
    # ═══════════════════════════════════════════════════════════════════════════

    client_secret_expires_at = fields.Datetime(
        string="Client Secret Expires At",
        help="When the client secret expires (empty = never)"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # RELATIONSHIPS
    # ═══════════════════════════════════════════════════════════════════════════

    authorization_code_ids = fields.One2many(
        'ik.oauth_authorization_code',
        'client_registration_id',
        string="Authorization Codes"
    )
    refresh_token_ids = fields.One2many(
        'ik.oauth_refresh_token',
        'client_registration_id',
        string="Refresh Tokens"
    )
    device_code_ids = fields.One2many(
        'ik.oauth_device_code',
        'client_registration_id',
        string="Device Codes"
    )

    # ═══════════════════════════════════════════════════════════════════════════
    # COMPUTED COUNTS (for stat buttons)
    # ═══════════════════════════════════════════════════════════════════════════

    refresh_token_count = fields.Integer(
        string="Refresh Token Count",
        compute='_compute_token_counts'
    )
    device_code_count = fields.Integer(
        string="Device Code Count",
        compute='_compute_token_counts'
    )

    @api.depends('refresh_token_ids', 'device_code_ids')
    def _compute_token_counts(self):
        for record in self:
            record.refresh_token_count = len(record.refresh_token_ids)
            record.device_code_count = len(record.device_code_ids)

    def action_view_refresh_tokens(self):
        """Open refresh tokens for this client."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': f'Refresh Tokens - {self.client_name}',
            'res_model': 'ik.oauth_refresh_token',
            'view_mode': 'list,form',
            'domain': [('client_registration_id', '=', self.id)],
            'context': {'default_client_registration_id': self.id},
        }

    def action_view_device_codes(self):
        """Open device codes for this client."""
        self.ensure_one()
        return {
            'type': 'ir.actions.act_window',
            'name': f'Device Codes - {self.client_name}',
            'res_model': 'ik.oauth_device_code',
            'view_mode': 'list,form',
            'domain': [('client_registration_id', '=', self.id)],
            'context': {'default_client_registration_id': self.id},
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # SQL CONSTRAINTS
    # ═══════════════════════════════════════════════════════════════════════════

    _sql_constraints = [
        ('client_id_unique', 'unique(client_id)', 'Client ID must be unique'),
    ]

    # ═══════════════════════════════════════════════════════════════════════════
    # METHODS
    # ═══════════════════════════════════════════════════════════════════════════

    @api.model_create_multi
    def create(self, vals_list):
        """Override create to auto-set allow_sensitive_data for mgx-* clients.

        Clients with client_name starting with 'mgx-' (Manganese CLI) are assumed
        to be authorized CLI tools that need access to sensitive data like
        credentials for automated deployments.
        """
        for vals in vals_list:
            client_name = vals.get('client_name', '')
            if client_name.startswith('mgx-') and 'allow_sensitive_data' not in vals:
                vals['allow_sensitive_data'] = True
        return super().create(vals_list)

    @api.model
    def _generate_client_id(self):
        """Generate a unique client ID with prefix.

        Returns:
            str: Client ID in format 'ikac_XXXXXXXX' (128 bits of entropy)
        """
        return f"ikac_{secrets.token_urlsafe(16)}"

    def generate_client_secret(self):
        """Generate a client secret.

        Returns:
            str: The generated secret (also stored in client_secret field)
        """
        self.ensure_one()
        secret = f"ikacs_{secrets.token_urlsafe(32)}"
        self.write({'client_secret': secret})
        return secret

    def validate_redirect_uri(self, redirect_uri):
        """Validate that redirect_uri is in the allowed list.

        Supports exact match and localhost with any port for CLI tools.

        Args:
            redirect_uri: URI to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If URI is not allowed
        """
        self.ensure_one()
        allowed = [u.strip() for u in (self.redirect_uris or '').split('\n') if u.strip()]

        # Exact match
        if redirect_uri in allowed:
            return True

        # Localhost pattern matching (for CLI tools with dynamic ports)
        parsed = urlparse(redirect_uri)
        if parsed.hostname in ('localhost', '127.0.0.1'):
            for pattern in allowed:
                if self._match_localhost_pattern(redirect_uri, pattern):
                    return True

        raise ValidationError(
            f"redirect_uri '{redirect_uri}' is not registered for this client"
        )

    def _match_localhost_pattern(self, uri, pattern):
        """Check if URI matches a localhost pattern with wildcard port.

        Args:
            uri: The actual redirect URI
            pattern: The registered pattern (may contain :* for any port)

        Returns:
            bool: True if matches
        """
        if ':*' not in pattern:
            return False

        parsed_uri = urlparse(uri)
        # Replace :* with a dummy port for parsing
        parsed_pattern = urlparse(pattern.replace(':*', ':9999'))

        # Must be same scheme (http for localhost)
        if parsed_uri.scheme != parsed_pattern.scheme:
            return False

        # Must be localhost
        if parsed_uri.hostname not in ('localhost', '127.0.0.1'):
            return False
        if parsed_pattern.hostname not in ('localhost', '127.0.0.1'):
            return False

        # Path must match
        if parsed_uri.path != parsed_pattern.path:
            return False

        return True

    @api.model
    def _get_all_scopes_supported(self):
        """Aggregate scopes from all active OAuth clients.

        Returns the union of allowed_scopes across all active client
        registrations. This represents the full set of scopes the
        authorization server can issue.

        Returns:
            list: Sorted list of unique scope strings
        """
        clients = self.sudo().search([('active', '=', True)])
        scopes = set()
        for client in clients:
            if client.allowed_scopes:
                scopes.update(client.allowed_scopes.split())
        return sorted(scopes) if scopes else []

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC HELPERS — REDIRECT URI ALLOWLIST (RFC 7591 DCR)
    # ═══════════════════════════════════════════════════════════════════════════
    # These are pure-logic classmethods extracted from OAuthController so that
    # downstream addons (e.g., inouk_mcp) can reuse the same redirect_uri
    # validation rules without depending on the HTTP controller.

    @api.model
    def match_redirect_uri_pattern(self, uri, patterns):
        """Check if URI matches any allowed pattern from the given list.

        Pure-logic classmethod (no DB access, no Werkzeug). Same rules as
        the historical OAuthController._validate_redirect_uri_pattern:

        - Localhost (http://localhost or http://127.0.0.1):
            - HTTPS rejected.
            - Any port allowed if a pattern with ':*' on the same path exists.
        - Non-localhost:
            - Exact string match against the patterns list.
            - fnmatch wildcard match (e.g. ``https://*.example.com/cb``).
        - Custom schemes (e.g. mobile apps) fall through to fnmatch.

        Args:
            uri: str. Candidate redirect URI.
            patterns: list[str]. Allowlist patterns (already split + stripped).

        Returns:
            bool: True if uri matches at least one pattern.
        """
        parsed = urlparse(uri)

        # Special handling for localhost (CLI applications)
        if parsed.hostname in ('localhost', '127.0.0.1'):
            if parsed.scheme != 'http':
                return False
            for pattern in patterns:
                if 'localhost:*' in pattern or '127.0.0.1:*' in pattern:
                    pattern_parsed = urlparse(pattern.replace(':*', ':9999'))
                    if parsed.path == pattern_parsed.path:
                        return True
            return False

        # Exact match
        if uri in patterns:
            return True

        # fnmatch-style pattern matching
        for pattern in patterns:
            if fnmatch.fnmatch(uri, pattern):
                return True

        return False

    @api.model
    def get_global_redirect_patterns(self):
        """Return the server-wide allowlist of redirect URI patterns.

        Reads ``ir.config_parameter`` ``inouk_api_auth.oauth_allowed_redirect_patterns``.
        Falls back to a hardcoded default (Claude.ai callbacks + localhost) if
        the parameter is unset or empty.

        Used by the global ``/oauth/register`` endpoint (non-MCP). Per-resource
        consumers (e.g. inouk_mcp per-instance DCR) must NOT call this method;
        they pass their own pattern list to ``match_redirect_uri_pattern``.

        Returns:
            list[str]: fnmatch patterns, one per non-empty line.
        """
        patterns = self.env['ir.config_parameter'].sudo().get_param(
            'inouk_api_auth.oauth_allowed_redirect_patterns',
            # Default: Claude.ai callbacks + localhost for CLI
            'https://claude.ai/api/mcp/auth_callback\n'
            'https://claude.com/api/mcp/auth_callback\n'
            'http://localhost:*/callback\n'
            'http://127.0.0.1:*/callback'
        )
        return [p.strip() for p in patterns.split('\n') if p.strip()]

    def validate_scope(self, requested_scope):
        """Filter the requested scope against this client's allowed_scopes.

        Behavior aligns with RFC 6749 §3.3: when the request includes a scope
        parameter, the server returns the intersection (requested ∩ allowed).
        When the request omits scope, the server falls back to the client's
        default_scopes. If default_scopes is also empty, the client gets all
        its allowed_scopes as a last-resort default.

        Why the allowed_scopes fallback is necessary:
        Real-world MCP clients (Claude.ai, Claude Desktop) omit the scope
        parameter in both DCR and authorize requests. RFC 7591 (DCR) says
        "if scope is omitted, the server MAY register with a default set"
        but doesn't mandate it. The per-instance DCR endpoint (inouk_mcp)
        defaults allowed_scopes to the full provider vocabulary, but the
        global DCR endpoint (inouk_api_auth) has no provider context and
        stores whatever the client sends — which is nothing.
        At authorize time, RFC 6749 §3.3 says the server "MUST either
        process the request using a pre-defined default value or fail".
        Without this fallback, scope-less clients get an empty token that
        is rejected by every scope-gated endpoint.

        Args:
            requested_scope: Space-separated scope string (or None/empty).

        Returns:
            str: Space-separated validated scope string, or '' if no overlap.
        """
        self.ensure_one()
        allowed = set((self.allowed_scopes or '').split())
        if requested_scope:
            requested = set(requested_scope.split())
            valid = requested & allowed
        else:
            defaults = set((self.default_scopes or '').split())
            # Fallback: when neither scope nor default_scopes are set,
            # grant the client its full allowed vocabulary rather than
            # issuing a useless empty-scope token.
            valid = defaults & allowed if defaults else allowed
        return ' '.join(sorted(valid)) if valid else ''

    def has_grant_type(self, grant_type):
        """Check if client supports a specific grant type.

        Args:
            grant_type: The grant type to check (e.g., 'authorization_code',
                       'urn:ietf:params:oauth:grant-type:device_code')

        Returns:
            bool: True if grant type is allowed
        """
        self.ensure_one()
        grant_types = (self.grant_types or '').replace(',', ' ').split()
        return grant_type in grant_types

    @api.constrains('redirect_uris')
    def _check_redirect_uris(self):
        """Validate redirect URIs format.

        - HTTPS required for non-localhost URIs
        - localhost/127.0.0.1 can use HTTP (for CLI tools)
        - Custom schemes allowed (for future mobile apps)
        """
        for record in self:
            if not record.redirect_uris:
                continue
            for uri in record.redirect_uris.split('\n'):
                uri = uri.strip()
                if not uri:
                    continue

                parsed = urlparse(uri)

                # Allow localhost with HTTP (for CLI tools)
                if parsed.hostname in ('localhost', '127.0.0.1'):
                    if parsed.scheme != 'http':
                        raise ValidationError(
                            f"Localhost redirect URIs must use http: {uri}"
                        )
                    continue

                # Allow custom schemes (for mobile apps)
                if parsed.scheme and '://' in uri and parsed.scheme not in ('http', 'https'):
                    continue

                # Require HTTPS for all other URIs
                if not uri.startswith('https://'):
                    raise ValidationError(
                        f"Non-localhost redirect URIs must use HTTPS: {uri}"
                    )

    @api.constrains('token_endpoint_auth_method', 'client_secret')
    def _check_client_secret(self):
        """Ensure client_secret is set if auth method requires it."""
        for record in self:
            if record.token_endpoint_auth_method in ('client_secret_post', 'client_secret_basic'):
                if not record.client_secret:
                    raise ValidationError(
                        f"Client secret is required for auth method: {record.token_endpoint_auth_method}"
                    )
