# -*- coding: utf-8 -*-
"""Tests for OAuth 2.1 Authorization Code flow.

These tests verify the core OAuth 2.1 functionality:
- Client registration
- Authorization codes (including PKCE)
- Refresh tokens
- Device code flow
"""

import secrets
import hashlib
import base64

from odoo.tests.common import TransactionCase
from odoo.tests import tagged
from odoo.exceptions import ValidationError
from odoo import fields


@tagged('post_install', '-at_install')
class TestOAuthClientRegistration(TransactionCase):
    """Tests for OAuth 2.1 Client Registration model."""

    def test_client_id_generation(self):
        """Test that client_id is generated with correct prefix."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })
        self.assertTrue(client.client_id.startswith('ikac_'))
        self.assertGreater(len(client.client_id), 20)  # ikac_ + base64 token

    def test_client_secret_generation(self):
        """Test client secret generation."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })
        secret = client.generate_client_secret()
        self.assertTrue(secret.startswith('ikacs_'))
        self.assertEqual(client.client_secret, secret)

    def test_redirect_uri_validation_https(self):
        """Test that non-localhost URIs require HTTPS."""
        with self.assertRaises(ValidationError):
            self.env['ik.oauth_client_registration'].create({
                'client_name': 'Test Client',
                'redirect_uris': 'http://example.com/callback',  # Should fail - no HTTPS
            })

    def test_redirect_uri_validation_localhost(self):
        """Test that localhost URIs allow HTTP."""
        # Should not raise
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'http://localhost:8080/callback',
        })
        self.assertTrue(client.id)

    def test_redirect_uri_exact_match(self):
        """Test exact redirect URI matching."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })
        # Should pass
        self.assertTrue(client.validate_redirect_uri('https://example.com/callback'))
        # Should fail
        with self.assertRaises(ValidationError):
            client.validate_redirect_uri('https://example.com/other')

    def test_scope_validation(self):
        """Test scope validation and filtering."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'allowed_scopes': 'mcp:discovery mcp:metadata',
            'default_scopes': 'mcp:discovery',
        })

        # Request allowed scope
        result = client.validate_scope('mcp:discovery')
        self.assertEqual(result, 'mcp:discovery')

        # Request multiple allowed scopes
        result = client.validate_scope('mcp:discovery mcp:metadata')
        self.assertIn('mcp:discovery', result)
        self.assertIn('mcp:metadata', result)

        # Request disallowed scope - should be filtered out
        result = client.validate_scope('mcp:operations')
        # Returns default_scopes when no valid scopes
        self.assertEqual(result, 'mcp:discovery')

    def test_has_grant_type(self):
        """Test grant type checking."""
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'grant_types': 'authorization_code,refresh_token',
        })
        self.assertTrue(client.has_grant_type('authorization_code'))
        self.assertTrue(client.has_grant_type('refresh_token'))
        self.assertFalse(client.has_grant_type('client_credentials'))


@tagged('post_install', '-at_install')
class TestOAuthAuthorizationCode(TransactionCase):
    """Tests for OAuth 2.1 Authorization Code model."""

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })

    def test_code_generation(self):
        """Test authorization code generation."""
        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'test_challenge',
            'code_challenge_method': 'S256',
        })
        self.assertGreater(len(auth_code.code), 40)

    def test_code_single_use(self):
        """Test that authorization codes can only be used once."""
        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'test_challenge',
            'code_challenge_method': 'S256',
        })

        # First use should succeed
        auth_code.consume()
        self.assertTrue(auth_code.used)

        # Second use should fail
        with self.assertRaises(ValidationError):
            auth_code.consume()

    def test_code_expiration(self):
        """Test that expired codes cannot be consumed."""
        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': 'test_challenge',
            'code_challenge_method': 'S256',
            # Set to past
            'expires_at': fields.Datetime.subtract(fields.Datetime.now(), seconds=60),
        })

        with self.assertRaises(ValidationError):
            auth_code.consume()


@tagged('post_install', '-at_install')
class TestOAuthPKCE(TransactionCase):
    """Tests for PKCE (RFC 7636) implementation."""

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
            'redirect_uris': 'https://example.com/callback',
        })

    def _generate_pkce_pair(self):
        """Generate a valid code_verifier and code_challenge pair."""
        verifier = secrets.token_urlsafe(43)  # 43-128 chars
        digest = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        return verifier, challenge

    def test_pkce_s256_valid(self):
        """Test valid PKCE S256 verification."""
        verifier, challenge = self._generate_pkce_pair()

        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })

        # Should pass
        self.assertTrue(auth_code.validate_pkce(verifier))

    def test_pkce_s256_invalid(self):
        """Test invalid PKCE S256 verification."""
        _, challenge = self._generate_pkce_pair()

        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })

        # Wrong verifier should fail
        with self.assertRaises(ValidationError):
            auth_code.validate_pkce('wrong_verifier_that_is_at_least_43_chars_long')

    def test_pkce_verifier_length(self):
        """Test PKCE verifier length validation (43-128 chars)."""
        _, challenge = self._generate_pkce_pair()

        auth_code = self.env['ik.oauth_authorization_code'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'redirect_uri': 'https://example.com/callback',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
        })

        # Too short
        with self.assertRaises(ValidationError):
            auth_code.validate_pkce('too_short')


@tagged('post_install', '-at_install')
class TestOAuthRefreshToken(TransactionCase):
    """Tests for OAuth 2.1 Refresh Token model."""

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })

    def test_token_generation(self):
        """Test refresh token generation."""
        refresh_token = self.env['ik.oauth_refresh_token'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'scope': 'mcp:discovery',
        })
        self.assertTrue(refresh_token.token.startswith('ikrt_'))

    def test_token_validation(self):
        """Test refresh token validation."""
        refresh_token = self.env['ik.oauth_refresh_token'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'scope': 'mcp:discovery',
        })
        # Should pass
        self.assertTrue(refresh_token.validate())

    def test_token_revocation(self):
        """Test refresh token revocation."""
        refresh_token = self.env['ik.oauth_refresh_token'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'scope': 'mcp:discovery',
        })

        refresh_token.revoke()
        self.assertTrue(refresh_token.revoked)

        # Should fail validation after revocation
        with self.assertRaises(ValidationError):
            refresh_token.validate()

    def test_token_use_count(self):
        """Test refresh token use counting."""
        refresh_token = self.env['ik.oauth_refresh_token'].create({
            'client_registration_id': self.client.id,
            'user_id': self.env.user.id,
            'scope': 'mcp:discovery',
        })

        self.assertEqual(refresh_token.use_count, 0)
        refresh_token.use()
        self.assertEqual(refresh_token.use_count, 1)
        refresh_token.use()
        self.assertEqual(refresh_token.use_count, 2)


@tagged('post_install', '-at_install')
class TestOAuthDeviceCode(TransactionCase):
    """Tests for OAuth 2.1 Device Code flow (RFC 8628)."""

    def setUp(self):
        super().setUp()
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test CLI',
            'grant_types': 'urn:ietf:params:oauth:grant-type:device_code,refresh_token',
        })

    def test_device_code_generation(self):
        """Test device code and user code generation."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(
            self.client,
            scope='mcp:discovery mcp:metadata',
        )

        # Check response structure (RFC 8628)
        self.assertIn('device_code', response)
        self.assertIn('user_code', response)
        self.assertIn('verification_uri', response)
        self.assertIn('verification_uri_complete', response)
        self.assertIn('expires_in', response)
        self.assertIn('interval', response)

        # Check user_code format (XXXX-XXXX)
        import re
        self.assertRegex(response['user_code'], r'^[A-Z0-9]{4}-[A-Z0-9]{4}$')

    def test_device_code_authorization_pending(self):
        """Test polling returns authorization_pending before user authorizes."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # Check status - should be pending
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'authorization_pending')

    def test_device_code_authorize(self):
        """Test user authorization flow."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(
            self.client,
            scope='mcp:discovery',
        )
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # User authorizes
        device_auth.authorize(self.env.user)

        self.assertEqual(device_auth.state, 'authorized')
        self.assertEqual(device_auth.user_id, self.env.user)
        self.assertTrue(device_auth.authorization_code_id)

    def test_device_code_deny(self):
        """Test user denial flow."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # User denies
        device_auth.deny()

        self.assertEqual(device_auth.state, 'denied')

        # Polling should return access_denied
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'access_denied')

    def test_device_code_expiration(self):
        """Test device code expiration."""
        DeviceCode = self.env['ik.oauth_device_code']

        response = DeviceCode.create_device_authorization(self.client)
        device_auth = DeviceCode.search([('device_code', '=', response['device_code'])])

        # Force expiration
        device_auth.write({
            'expires_at': fields.Datetime.subtract(fields.Datetime.now(), seconds=60),
        })

        # Polling should return expired_token
        status = device_auth.check_authorization_status()
        self.assertEqual(status.get('error'), 'expired_token')


@tagged('post_install', '-at_install')
class TestOAuth21TokenFields(TransactionCase):
    """Tests for OAuth 2.1 token fields and scope checking."""

    def test_has_scope(self):
        """Test scope checking on tokens."""
        Token = self.env['ik.api_auth_token']

        # Create a token with OAuth 2.1 fields
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })

        token = Token.create({
            'name': 'Test Token',
            'user_id': self.env.user.id,
            'token_type': 'header',
            'oauth21_client_registration_id': client.id,
            'oauth21_scope': 'mcp:discovery mcp:metadata',
        })

        # Should have granted scopes
        self.assertTrue(token.has_scope('mcp:discovery'))
        self.assertTrue(token.has_scope('mcp:metadata'))

        # Should not have ungranted scopes
        self.assertFalse(token.has_scope('mcp:operations'))

    def test_is_oauth21_token(self):
        """Test is_oauth21_token computed field."""
        Token = self.env['ik.api_auth_token']

        # Non-OAuth21 token
        token1 = Token.create({
            'name': 'Regular Token',
            'user_id': self.env.user.id,
            'token_type': 'header',
        })
        self.assertFalse(token1.is_oauth21_token)

        # OAuth21 token
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })
        token2 = Token.create({
            'name': 'OAuth21 Token',
            'user_id': self.env.user.id,
            'token_type': 'header',
            'oauth21_client_registration_id': client.id,
        })
        self.assertTrue(token2.is_oauth21_token)


@tagged('post_install', '-at_install')
class TestRedirectUriPatternMatch(TransactionCase):
    """Tests for match_redirect_uri_pattern classmethod (extracted from controller)."""

    def setUp(self):
        super().setUp()
        self.ClientReg = self.env['ik.oauth_client_registration']

    def test_exact_match(self):
        """Exact URI match against patterns list."""
        patterns = ['https://claude.ai/api/mcp/auth_callback']
        self.assertTrue(self.ClientReg.match_redirect_uri_pattern(
            'https://claude.ai/api/mcp/auth_callback', patterns))
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'https://claude.ai/api/mcp/other', patterns))

    def test_fnmatch_wildcard(self):
        """fnmatch-style wildcards (e.g., subdomains, path globs)."""
        patterns = ['https://chatgpt.com/connector/oauth/*']
        self.assertTrue(self.ClientReg.match_redirect_uri_pattern(
            'https://chatgpt.com/connector/oauth/U4Rcy6m-N9xE', patterns))
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'https://chatgpt.com/other', patterns))

    def test_localhost_any_port(self):
        """Localhost with :* pattern allows any port (CLI tools)."""
        patterns = ['http://localhost:*/callback']
        self.assertTrue(self.ClientReg.match_redirect_uri_pattern(
            'http://localhost:8080/callback', patterns))
        self.assertTrue(self.ClientReg.match_redirect_uri_pattern(
            'http://localhost:65000/callback', patterns))
        # Different path → fail
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'http://localhost:8080/other', patterns))

    def test_localhost_rejects_https(self):
        """Localhost MUST use http:// (not https://)."""
        patterns = ['http://localhost:*/callback']
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'https://localhost:8080/callback', patterns))

    def test_127_0_0_1_alias(self):
        """127.0.0.1 is treated like localhost."""
        patterns = ['http://127.0.0.1:*/callback']
        self.assertTrue(self.ClientReg.match_redirect_uri_pattern(
            'http://127.0.0.1:8080/callback', patterns))

    def test_no_match_returns_false(self):
        """Unmatched URI returns False (not None, not raise)."""
        patterns = ['https://claude.ai/api/mcp/auth_callback']
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'https://attacker.example/callback', patterns))

    def test_empty_patterns_list(self):
        """Empty patterns list = deny all."""
        self.assertFalse(self.ClientReg.match_redirect_uri_pattern(
            'https://claude.ai/api/mcp/auth_callback', []))


@tagged('post_install', '-at_install')
class TestGlobalRedirectPatterns(TransactionCase):
    """Tests for get_global_redirect_patterns classmethod."""

    def test_default_when_unset(self):
        """Default patterns returned when ICP is unset."""
        ICP = self.env['ir.config_parameter'].sudo()
        # Ensure ICP is unset
        existing = ICP.search([('key', '=', 'inouk_api_auth.oauth_allowed_redirect_patterns')])
        existing.unlink()
        patterns = self.env['ik.oauth_client_registration'].get_global_redirect_patterns()
        # Hardcoded fallback contains Claude.ai + localhost
        self.assertIn('https://claude.ai/api/mcp/auth_callback', patterns)
        self.assertIn('http://localhost:*/callback', patterns)

    def test_icp_value_overrides_default(self):
        """ICP value, when set, takes precedence."""
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param(
            'inouk_api_auth.oauth_allowed_redirect_patterns',
            'https://example.com/cb\nhttps://other.test/cb',
        )
        patterns = self.env['ik.oauth_client_registration'].get_global_redirect_patterns()
        self.assertEqual(patterns, ['https://example.com/cb', 'https://other.test/cb'])

    def test_blank_lines_stripped(self):
        """Blank lines and whitespace stripped from ICP value."""
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param(
            'inouk_api_auth.oauth_allowed_redirect_patterns',
            '  https://a.test/cb  \n\n  https://b.test/cb\n',
        )
        patterns = self.env['ik.oauth_client_registration'].get_global_redirect_patterns()
        self.assertEqual(patterns, ['https://a.test/cb', 'https://b.test/cb'])


@tagged('post_install', '-at_install')
class TestIssueTokenPair(TransactionCase):
    """Tests for issue_token_pair classmethod (extracted from controller)."""

    def setUp(self):
        super().setUp()
        self.RefreshToken = self.env['ik.oauth_refresh_token']
        self.client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Test Client',
        })
        self.user = self.env.ref('base.user_admin')

    def test_returns_payload_dict(self):
        """Returns RFC 6749 dict (not Response, not record)."""
        payload = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:discovery mcp:read', None,
        )
        self.assertIsInstance(payload, dict)
        self.assertIn('access_token', payload)
        self.assertIn('refresh_token', payload)
        self.assertEqual(payload['token_type'], 'Bearer')
        self.assertEqual(payload['scope'], 'mcp:discovery mcp:read')
        self.assertGreater(payload['expires_in'], 0)

    def test_creates_access_and_refresh_records(self):
        """Persists ik.api_auth_token AND ik.oauth_refresh_token records."""
        payload = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', 'https://server/mcp/x/y',
        )
        access = self.env['ik.api_auth_token'].search([
            ('static_token', '=', payload['access_token']),
        ])
        self.assertEqual(len(access), 1)
        self.assertEqual(access.oauth21_client_registration_id, self.client)
        self.assertEqual(access.oauth21_scope, 'mcp:read')
        self.assertEqual(access.oauth21_resource, 'https://server/mcp/x/y')

        refresh = self.RefreshToken.search([('token', '=', payload['refresh_token'])])
        self.assertEqual(len(refresh), 1)
        self.assertEqual(refresh.client_registration_id, self.client)
        self.assertEqual(refresh.access_token_id, access)
        self.assertEqual(access.oauth21_refresh_token_id, refresh)

    def test_extra_access_vals_injected(self):
        """extra_access_vals merged into Token.create()."""
        # Use an existing field to avoid coupling test to a future model.
        payload = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
            extra_access_vals={'description': 'integration test marker'},
        )
        access = self.env['ik.api_auth_token'].search([
            ('static_token', '=', payload['access_token']),
        ])
        self.assertEqual(access.description, 'integration test marker')

    def test_extra_refresh_vals_injected(self):
        """extra_refresh_vals merged into RefreshToken.create()."""
        # ik.oauth_refresh_token has no Char field by default we can repurpose
        # safely; use 'scope' override as a marker (its value is also driven by
        # the positional arg, so we rely on the fact that extra_refresh_vals
        # wins via dict.update).
        payload = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
            extra_refresh_vals={'scope': 'mcp:read mcp:write'},
        )
        refresh = self.RefreshToken.search([('token', '=', payload['refresh_token'])])
        # extra_refresh_vals wins over the positional `scope` arg by design
        # (dict.update applies after the core vals are set).
        self.assertEqual(refresh.scope, 'mcp:read mcp:write')

    def test_rotation_revokes_old_refresh(self):
        """When rotation enabled, old refresh token is revoked on issuance."""
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param('inouk_api_auth.oauth_rotate_refresh_tokens', 'true')

        # Issue first pair, then refresh
        payload1 = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
        )
        old_refresh = self.RefreshToken.search([('token', '=', payload1['refresh_token'])])
        self.assertFalse(old_refresh.revoked)

        payload2 = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
            old_refresh_token=old_refresh,
        )
        # Old refresh now revoked, new one issued
        self.assertTrue(old_refresh.revoked)
        self.assertNotEqual(payload1['refresh_token'], payload2['refresh_token'])

    def test_no_rotation_reuses_refresh(self):
        """When rotation disabled, old refresh token is reused."""
        ICP = self.env['ir.config_parameter'].sudo()
        ICP.set_param('inouk_api_auth.oauth_rotate_refresh_tokens', 'false')

        payload1 = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
        )
        old_refresh = self.RefreshToken.search([('token', '=', payload1['refresh_token'])])
        old_use_count = old_refresh.use_count

        payload2 = self.RefreshToken.issue_token_pair(
            self.client, self.user, 'mcp:read', None,
            old_refresh_token=old_refresh,
        )
        # Same refresh_token, use_count incremented, not revoked
        self.assertEqual(payload1['refresh_token'], payload2['refresh_token'])
        self.assertFalse(old_refresh.revoked)
        self.assertEqual(old_refresh.use_count, old_use_count + 1)

        # Reset ICP for other tests
        ICP.set_param('inouk_api_auth.oauth_rotate_refresh_tokens', 'true')
