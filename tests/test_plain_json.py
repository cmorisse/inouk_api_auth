# -*- coding: utf-8 -*-
"""
Tests for ik_plain_json support in Odoo 18.

These tests validate that the json_plain_patch monkey-patch correctly handles
plain JSON requests/responses without JSON-RPC wrapping.

Test scenarios:
1. Basic echo - POST JSON body, receive plain JSON response
2. HTTP status codes via werkzeug.exceptions.HTTPException
3. Custom exceptions with status_code attribute
4. Datetime serialization
5. Response object pass-through
6. Error response format validation
"""
import json
import secrets

from odoo.tests.common import HttpCase, tagged


@tagged('post_install', '-at_install', 'plain_json')
class TestPlainJson(HttpCase):
    """Test ik_plain_json support for plain JSON (non-JSON-RPC) requests/responses."""

    def setUp(self):
        super().setUp()
        self.user_demo = self.env.ref('base.user_admin')
        self.token_value = secrets.token_hex(30)
        self.test_token = self.env['ik.api_auth_token'].create({
            'name': 'Plain JSON Test Token',
            'user_id': self.user_demo.id,
            'static_token': self.token_value,
            'token_type': 'bearer',
            'enforce_integrity': False,  # Disable for HTTP tests
        })
        self.test_endpoint_base = '/inouk/api_auth/test/plain_json'
        self.headers = {
            'Authorization': f'Bearer {self.token_value}',
            'Content-Type': 'application/json',
        }

    def _post_json(self, endpoint, data=None):
        """Helper to POST JSON to a plain_json endpoint."""
        url = f'{self.test_endpoint_base}/{endpoint}'
        return self.url_open(
            url,
            data=json.dumps(data or {}),
            headers=self.headers,
        )

    def test_echo_basic(self):
        """Test basic echo endpoint - plain JSON request/response."""
        test_data = {'message': 'hello', 'count': 42, 'nested': {'key': 'value'}}
        response = self._post_json('echo', test_data)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('Content-Type'), 'application/json')

        result = response.json()

        # Verify it's plain JSON (no JSON-RPC wrapper)
        self.assertNotIn('jsonrpc', result)
        self.assertNotIn('result', result)

        # Verify echo response
        self.assertEqual(result.get('status'), 'success')
        self.assertEqual(result.get('echo'), test_data)

    def test_echo_empty_body(self):
        """Test echo with empty JSON body."""
        response = self._post_json('echo', {})

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result.get('status'), 'success')
        self.assertEqual(result.get('echo'), {})

    def test_error_400_bad_request(self):
        """Test HTTPException BadRequest returns 400 status code."""
        response = self._post_json('error_400', {})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers.get('Content-Type'), 'application/json')

        result = response.json()

        # Verify plain JSON error format (no JSON-RPC wrapper)
        self.assertNotIn('jsonrpc', result)
        self.assertEqual(result.get('status'), 'error')
        self.assertIn('error', result)

    def test_error_404_not_found(self):
        """Test HTTPException NotFound returns 404 status code."""
        response = self._post_json('error_404', {})

        self.assertEqual(response.status_code, 404)
        result = response.json()
        self.assertEqual(result.get('status'), 'error')

    def test_error_403_forbidden(self):
        """Test HTTPException Forbidden returns 403 status code."""
        response = self._post_json('error_403', {})

        self.assertEqual(response.status_code, 403)
        result = response.json()
        self.assertEqual(result.get('status'), 'error')

    def test_error_custom_status_code(self):
        """Test custom exception with status_code=422 returns 422."""
        response = self._post_json('error_custom', {})

        self.assertEqual(response.status_code, 422)
        result = response.json()
        self.assertEqual(result.get('status'), 'error')
        self.assertIn('error', result)

    def test_error_500_internal(self):
        """Test generic exception returns 500 status code."""
        response = self._post_json('error_500', {})

        self.assertEqual(response.status_code, 500)
        result = response.json()
        self.assertEqual(result.get('status'), 'error')

    def test_datetime_serialization(self):
        """Test datetime objects are correctly serialized."""
        response = self._post_json('datetime', {})

        self.assertEqual(response.status_code, 200)
        result = response.json()

        # Verify datetime is serialized (should be ISO format string)
        self.assertIn('datetime', result)
        self.assertIn('date', result)
        self.assertIsInstance(result['datetime'], str)
        self.assertIsInstance(result['date'], str)

        # Verify other types
        self.assertEqual(result['string'], 'test')
        self.assertEqual(result['number'], 42)

    def test_response_object_passthrough(self):
        """Test Response object is returned as-is."""
        response = self._post_json('response_object', {})

        # Should return 201 (custom status from Response object)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.headers.get('Content-Type'), 'application/json')
        self.assertEqual(response.headers.get('X-Custom-Header'), 'test-value')

        result = response.json()
        self.assertEqual(result.get('custom'), 'response')
        self.assertEqual(result.get('with_header'), True)

    def test_no_json_rpc_wrapper_in_success_response(self):
        """Verify successful response has no JSON-RPC wrapper."""
        response = self._post_json('echo', {'test': 'data'})

        self.assertEqual(response.status_code, 200)
        result = response.json()

        # These keys should NOT be present (JSON-RPC wrapper keys)
        self.assertNotIn('jsonrpc', result)
        self.assertNotIn('id', result)
        self.assertNotIn('result', result)

        # These keys SHOULD be present (our plain response)
        self.assertIn('status', result)
        self.assertIn('echo', result)

    def test_no_json_rpc_wrapper_in_error_response(self):
        """Verify error response has no JSON-RPC wrapper."""
        response = self._post_json('error_400', {})

        self.assertEqual(response.status_code, 400)
        result = response.json()

        # These keys should NOT be present (JSON-RPC error wrapper keys)
        self.assertNotIn('jsonrpc', result)
        self.assertNotIn('id', result)

        # Plain JSON error format
        self.assertIn('error', result)
        self.assertIn('status', result)
        self.assertEqual(result['status'], 'error')

    def test_content_type_header(self):
        """Verify Content-Type header is application/json."""
        response = self._post_json('echo', {'test': 'data'})

        self.assertEqual(response.status_code, 200)
        content_type = response.headers.get('Content-Type')
        self.assertIn('application/json', content_type)

    def test_without_authentication(self):
        """Test that endpoints require authentication."""
        url = f'{self.test_endpoint_base}/echo'
        # No Authorization header
        response = self.url_open(
            url,
            data=json.dumps({'test': 'data'}),
            headers={'Content-Type': 'application/json'},
        )

        # Should fail authentication - Odoo 18 JSON-RPC returns HTTP 200 with error in body
        result = response.json()
        # Check for either JSON-RPC error or plain error response
        is_error = ('error' in result) or (result.get('status') == 'error')
        self.assertTrue(is_error, f"Expected authentication error but got: {result}")

    def test_with_invalid_token(self):
        """Test that invalid token is rejected."""
        url = f'{self.test_endpoint_base}/echo'
        response = self.url_open(
            url,
            data=json.dumps({'test': 'data'}),
            headers={
                'Authorization': 'Bearer invalid_token_12345',
                'Content-Type': 'application/json',
            },
        )

        # Should fail authentication - Odoo 18 JSON-RPC returns HTTP 200 with error in body
        result = response.json()
        # Check for either JSON-RPC error or plain error response
        is_error = ('error' in result) or (result.get('status') == 'error')
        self.assertTrue(is_error, f"Expected authentication error but got: {result}")

    def test_nested_data_structure(self):
        """Test complex nested JSON structures are handled correctly."""
        complex_data = {
            'level1': {
                'level2': {
                    'level3': {
                        'value': 'deep',
                        'array': [1, 2, 3],
                    }
                },
                'array': ['a', 'b', 'c'],
            },
            'numbers': [1, 2.5, -3, 0],
            'boolean': True,
            'null': None,
        }
        response = self._post_json('echo', complex_data)

        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result.get('echo'), complex_data)
