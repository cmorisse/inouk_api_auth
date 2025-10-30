# -*- coding: utf-8 -*-
import secrets
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from odoo import fields
from odoo.tests.common import TransactionCase, tagged
from odoo.http import AuthenticationError


@tagged('post_install', '-at_install')
class TestAuthMethods(TransactionCase):
    """Test authentication methods"""

    def setUp(self):
        super().setUp()
        self.user_demo = self.env.ref('base.user_demo')
        self.token_value = secrets.token_hex(30)
        self.test_token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value,
            'token_type': 'bearer',
            'enforce_integrity': True,
        })

    def _create_mock_request(self, headers=None, url='https://test.example.com/api', params=None, args=None):
        """Create a mock request object"""
        mock_request = MagicMock()
        mock_request.httprequest.headers.get.side_effect = lambda h: (headers or {}).get(h)
        mock_request.httprequest.url = url
        mock_request.httprequest.environ.get.side_effect = lambda k: {
            'REMOTE_ADDR': '192.168.1.100',
            'HTTP_REFERER': 'https://test.example.com'
        }.get(k)
        mock_request.params = params or {}
        mock_request.httprequest.args.get.side_effect = lambda k: (args or {}).get(k)
        return mock_request

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_with_authorization_header(self, mock_request):
        """Test authentication with Authorization header"""
        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {self.token_value}'
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            # Call the authentication method
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            # Verify authentication
            self.assertEqual(mock_request.session.uid, self.user_demo.id)
            self.assertEqual(mock_request.uid, self.user_demo.id)
            self.assertEqual(mock_request.inouk_token_obj, self.test_token)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_with_gitlab_header(self, mock_request):
        """Test authentication with X-Gitlab-Token header"""
        gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value + 'gitlab',
            'token_type': 'xgitlabtoken',
        })

        mock_request = self._create_mock_request(headers={
            'X-Gitlab-Token': gitlab_token.static_token
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            self.assertEqual(mock_request.session.uid, self.user_demo.id)
            self.assertEqual(mock_request.uid, self.user_demo.id)
            self.assertEqual(mock_request.inouk_token_obj, gitlab_token)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_with_url_param(self, mock_request):
        """Test authentication with URL parameter"""
        mock_request = self._create_mock_request(params={
            'access_token': self.token_value
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            # Verify parameter was removed
            self.assertNotIn('access_token', mock_request.params)
            self.assertEqual(mock_request.session.uid, self.user_demo.id)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_missing_token(self, mock_request):
        """Test authentication failure when no token provided"""
        mock_request = self._create_mock_request()

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Missing required Authorization", str(cm.exception))

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_invalid_token(self, mock_request):
        """Test authentication failure with invalid token"""
        mock_request = self._create_mock_request(headers={
            'Authorization': 'Bearer invalid_token_value'
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_expired_token(self, mock_request):
        """Test authentication failure with expired token"""
        expired_token = self.env['ik.api_auth_token'].create({
            'name': 'Expired Token',
            'user_id': self.user_demo.id,
            'static_token': 'expired_token_value',
            'token_type': 'bearer',
            'expiration_ts': fields.Datetime.now() - timedelta(days=1),
        })

        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {expired_token.static_token}'
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_compromised_token(self, mock_request):
        """Test authentication failure with compromised token"""
        self.test_token.write({'is_compromised': True})

        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {self.token_value}'
        })

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_check_token_compromised_https_ok(self, mock_request):
        """Test compromission check passes for HTTPS (not compromised)"""
        mock_request = self._create_mock_request(
            url='https://test.example.com/api'
        )

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'https://test.example.com')
            self.assertFalse(is_compromised)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_check_token_compromised_http_fail(self, mock_request):
        """Test compromission check fails for HTTP (compromised)"""
        mock_request = self._create_mock_request(
            url='http://test.example.com/api'
        )

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'https://test.example.com')
            self.assertTrue(is_compromised)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_check_token_compromised_http_referer_fail(self, mock_request):
        """Test compromission check fails for HTTP referer (compromised)"""
        mock_request = self._create_mock_request(
            url='https://test.example.com/api'
        )

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'http://test.example.com')
            self.assertTrue(is_compromised)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_compromise_token_http_with_integrity(self, mock_request):
        """Test token gets compromised when received over HTTP with enforce_integrity=True"""
        mock_request = self._create_mock_request(
            url='http://test.example.com/api',
            headers={'Authorization': f'Bearer {self.token_value}'}
        )
        mock_request.env.cr.commit = MagicMock()

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError):
                ir_http._auth_method_ik_bearer()

            # Check token was compromised
            self.test_token.refresh()
            self.assertTrue(self.test_token.is_compromised)
            self.assertIn('Token expired by Muppy', self.test_token.security_log)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_bearer_http_without_integrity(self, mock_request):
        """Test authentication works over HTTP when enforce_integrity=False"""
        self.test_token.write({'enforce_integrity': False})

        mock_request = self._create_mock_request(
            url='http://test.example.com/api',
            headers={'Authorization': f'Bearer {self.token_value}'}
        )

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            # Should work but generate warning
            self.assertEqual(mock_request.session.uid, self.user_demo.id)
            self.assertFalse(self.test_token.is_compromised)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_awssigv4_success(self, mock_request):
        """Test successful AWS SigV4 authentication"""
        from unittest.mock import MagicMock

        # Create AWS SigV4 token
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.user_demo.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        mock_request = self._create_mock_request(
            url='https://test.example.com/api',
            headers={
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=example'
            }
        )
        mock_request.httprequest.method = 'GET'
        mock_request.httprequest.get_data.return_value = b''

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            with patch.object(self.env['ir.http'], '_validate_awssigv4_signature', return_value=True):
                ir_http = self.env['ir.http']
                ir_http._auth_method_ik_awssigv4()

                self.assertEqual(mock_request.session.uid, self.user_demo.id)
                self.assertEqual(mock_request.uid, self.user_demo.id)
                self.assertEqual(mock_request.inouk_token_obj, aws_token)

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_awssigv4_invalid_header(self, mock_request):
        """Test AWS SigV4 authentication with invalid header"""
        mock_request = self._create_mock_request(
            headers={'Authorization': 'Bearer invalid'}
        )

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AuthenticationError) as cm:
                ir_http._auth_method_ik_awssigv4()
            self.assertIn("Missing or invalid AWS4-HMAC-SHA256", str(cm.exception))

    @patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request')
    def test_auth_method_ik_awssigv4_invalid_signature(self, mock_request):
        """Test AWS SigV4 authentication with invalid signature"""
        # Create AWS SigV4 token
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.user_demo.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        mock_request = self._create_mock_request(
            headers={
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=invalid'
            }
        )
        mock_request.httprequest.method = 'GET'
        mock_request.httprequest.get_data.return_value = b''

        with patch('odoo.addons.inouk_api_auth.models.ir_http_extension.request', mock_request):
            with patch.object(self.env['ir.http'], '_validate_awssigv4_signature', return_value=False):
                ir_http = self.env['ir.http']
                with self.assertRaises(AuthenticationError) as cm:
                    ir_http._auth_method_ik_awssigv4()
                self.assertIn("Invalid AWS Signature", str(cm.exception))