# -*- coding: utf-8 -*-
import json
import secrets
from unittest.mock import patch

from odoo.tests.common import HttpCase, tagged
from odoo.http import AuthenticationError


@tagged('post_install', '-at_install')
class TestControllers(HttpCase):
    """Test API controllers"""

    def setUp(self):
        super().setUp()
        self.user_demo = self.env.ref('base.user_demo')
        self.token_value = secrets.token_hex(30)
        self.test_token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value,
            'token_type': 'bearer',
            'enforce_integrity': False,  # Disable for HTTP tests
        })

    def test_hello_v1_with_bearer_token(self):
        """Test V1 endpoint (deprecated decorator) with Bearer token"""
        url = '/inouk/api_auth/v1/hello'
        headers = {'Authorization': f'Bearer {self.token_value}'}

        response = self.url_open(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello ! Call Ok', response.text)
        self.assertIn(self.test_token.name, response.text)

    def test_hello_v2_with_bearer_token(self):
        """Test V2 endpoint (new auth method) with Bearer token"""
        url = '/inouk/api_auth/v2/hello'
        headers = {'Authorization': f'Bearer {self.token_value}'}

        response = self.url_open(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello v2! Call Ok', response.text)
        self.assertIn(self.test_token.name, response.text)
        self.assertIn(self.user_demo.name, response.text)

    def test_hello_v1_with_gitlab_token(self):
        """Test V1 endpoint with X-Gitlab-Token"""
        gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value + '_gitlab',
            'token_type': 'xgitlabtoken',
            'enforce_integrity': False,
        })

        url = '/inouk/api_auth/v1/hello'
        headers = {'X-Gitlab-Token': gitlab_token.static_token}

        response = self.url_open(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello ! Call Ok', response.text)

    def test_hello_v2_with_gitlab_token(self):
        """Test V2 endpoint with X-Gitlab-Token"""
        gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Token V2',
            'user_id': self.user_demo.id,
            'static_token': self.token_value + '_gitlab_v2',
            'token_type': 'xgitlabtoken',
            'enforce_integrity': False,
        })

        url = '/inouk/api_auth/v2/hello'
        headers = {'X-Gitlab-Token': gitlab_token.static_token}

        response = self.url_open(url, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello v2! Call Ok', response.text)

    def test_hello_v1_with_url_parameter(self):
        """Test V1 endpoint with access_token URL parameter"""
        url = f'/inouk/api_auth/v1/hello?access_token={self.token_value}'

        response = self.url_open(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello ! Call Ok', response.text)

    def test_hello_v2_with_url_parameter(self):
        """Test V2 endpoint with access_token URL parameter"""
        url = f'/inouk/api_auth/v2/hello?access_token={self.token_value}'

        response = self.url_open(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello v2! Call Ok', response.text)

    def test_hello_v1_without_token(self):
        """Test V1 endpoint without token - should fail"""
        url = '/inouk/api_auth/v1/hello'

        response = self.url_open(url)
        # Should return error (likely 403 or 500)
        self.assertNotEqual(response.status_code, 200)

    def test_hello_v2_without_token(self):
        """Test V2 endpoint without token - should fail"""
        url = '/inouk/api_auth/v2/hello'

        response = self.url_open(url)
        # Should return error (likely 403 or 500)
        self.assertNotEqual(response.status_code, 200)

    def test_hello_v1_with_invalid_token(self):
        """Test V1 endpoint with invalid token"""
        url = '/inouk/api_auth/v1/hello'
        headers = {'Authorization': 'Bearer invalid_token_123'}

        response = self.url_open(url)
        # Should return error
        self.assertNotEqual(response.status_code, 200)

    def test_hello_v2_with_invalid_token(self):
        """Test V2 endpoint with invalid token"""
        url = '/inouk/api_auth/v2/hello'
        headers = {'Authorization': 'Bearer invalid_token_123'}

        response = self.url_open(url)
        # Should return error
        self.assertNotEqual(response.status_code, 200)

    def test_hello_v1_with_expired_token(self):
        """Test V1 endpoint with expired token"""
        from datetime import datetime, timedelta
        from odoo import fields

        expired_token = self.env['ik.api_auth_token'].create({
            'name': 'Expired Token',
            'user_id': self.user_demo.id,
            'static_token': 'expired_token_value',
            'token_type': 'bearer',
            'expiration_ts': fields.Datetime.now() - timedelta(days=1),
            'enforce_integrity': False,
        })

        url = '/inouk/api_auth/v1/hello'
        headers = {'Authorization': f'Bearer {expired_token.static_token}'}

        response = self.url_open(url, headers=headers)
        self.assertNotEqual(response.status_code, 200)

    def test_hello_v2_with_expired_token(self):
        """Test V2 endpoint with expired token"""
        from datetime import datetime, timedelta
        from odoo import fields

        expired_token = self.env['ik.api_auth_token'].create({
            'name': 'Expired Token V2',
            'user_id': self.user_demo.id,
            'static_token': 'expired_token_value_v2',
            'token_type': 'bearer',
            'expiration_ts': fields.Datetime.now() - timedelta(days=1),
            'enforce_integrity': False,
        })

        url = '/inouk/api_auth/v2/hello'
        headers = {'Authorization': f'Bearer {expired_token.static_token}'}

        response = self.url_open(url, headers=headers)
        self.assertNotEqual(response.status_code, 200)

    def test_hello_both_endpoints_same_token(self):
        """Test that both V1 and V2 endpoints work with the same token"""
        headers = {'Authorization': f'Bearer {self.token_value}'}

        # Test V1
        response_v1 = self.url_open('/inouk/api_auth/v1/hello', headers=headers)
        self.assertEqual(response_v1.status_code, 200)
        self.assertIn('Hello ! Call Ok', response_v1.text)

        # Test V2
        response_v2 = self.url_open('/inouk/api_auth/v2/hello', headers=headers)
        self.assertEqual(response_v2.status_code, 200)
        self.assertIn('Hello v2! Call Ok', response_v2.text)

        # Both should reference the same token but with different messages
        self.assertNotEqual(response_v1.text, response_v2.text)

    def test_token_case_insensitive_bearer(self):
        """Test that Bearer token header is case insensitive"""
        # Test with different case variations
        test_cases = [
            f'Bearer {self.token_value}',
            f'bearer {self.token_value}',
            f'BEARER {self.token_value}',
            f'BeArEr {self.token_value}',
        ]

        for auth_header in test_cases:
            headers = {'Authorization': auth_header}
            response = self.url_open('/inouk/api_auth/v2/hello', headers=headers)
            self.assertEqual(response.status_code, 200, f"Failed for auth header: {auth_header}")
            self.assertIn('Hello v2! Call Ok', response.text)

    def test_token_without_bearer_prefix_in_gitlab_header(self):
        """Test GitLab token without Bearer prefix"""
        gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Raw Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value + '_raw',
            'token_type': 'xgitlabtoken',
            'enforce_integrity': False,
        })

        # GitLab tokens don't use Bearer prefix
        headers = {'X-Gitlab-Token': gitlab_token.static_token}

        response = self.url_open('/inouk/api_auth/v2/hello', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Hello v2! Call Ok', response.text)