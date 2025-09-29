import logging
import secrets
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.exceptions import UserError

from ..controllers.auth import TOKEN_STATUS_BEARER_URL

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('xgitlabtoken', "X-Gitlab-Token"),
]


class InoukAPIAuthToken(models.Model):
    _inherit = 'ik.api_auth_token'

    # Add X-Gitlab-Token to token type selection
    token_type = fields.Selection(selection_add=TOKEN_TYPES_LIST)

    def btn_regenerate_credentials(self):
        """Regenerate credentials - X-Gitlab-Token specific implementation"""
        self.ensure_one()

        if self.token_type == 'xgitlabtoken':
            # Generate standard hex token
            self.static_token = secrets.token_hex(30)

            # Return a notification with the token
            return {
                'type': 'ir.actions.client',
                'tag': 'display_notification',
                'params': {
                    'title': 'X-Gitlab-Token Generated',
                    'message': f'<strong>Token:</strong> {self.static_token}<br/><br/><span style="color: #ff6b35;">⚠️ Save this token immediately - it cannot be retrieved later!</span>',
                    'type': 'warning',
                    'sticky': True,
                }
            }
        else:
            return super().btn_regenerate_credentials()

    def compute__xgitlabtoken_test_curl(self):
        """Generate X-Gitlab-Token curl command for testing"""
        self.ensure_one()
        if not self.static_token:
            return "# Generate token first"

        # Use unified token status URL for X-Gitlab-Token (uses Bearer endpoint)
        _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        if not _base_url:
            return "# Configure web.base.url first"

        token_status_url = urljoin(_base_url, TOKEN_STATUS_BEARER_URL)

        if self.test_use_header:
            return f"curl --header 'X-Gitlab-Token: {self.static_token}' '{token_status_url}'"
        else:
            return f"curl '{token_status_url}?access_token={self.static_token}'"

    def compute__test_curl(self):
        """Override to handle X-Gitlab-Token cURL generation"""
        for record in self:
            if record.token_type == 'xgitlabtoken':
                record.hello_curl = record.compute__xgitlabtoken_test_curl()
            else:
                super().compute__test_curl()

    def compute__python_examples(self):
        """Generate Python requests examples for X-Gitlab-Token authentication"""
        for record in self:
            if record.token_type == 'xgitlabtoken':
                _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                if not _base_url:
                    record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
                else:
                    token_value = record.static_token or 'YOUR_TOKEN_HERE'
                    bearer_status_url = urljoin(_base_url, TOKEN_STATUS_BEARER_URL)

                    header_name = 'X-Gitlab-Token'
                    header_value = token_value
                    title = "X-Gitlab-Token Authentication"

                    examples_html = f"""
                    <div style='padding: 10px; font-family: monospace;'>
                    <h3 style='color: #2e7bcf; margin-bottom: 15px;'>{title}</h3>

                    <div style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; margin-bottom: 15px;'>
                        <strong>⚠️ Security Note:</strong> X-Gitlab-Token tokens are only shown once when generated.
                        Store them securely - they cannot be retrieved later (only regenerated).
                    </div>

                    <h4 style='color: #666; margin-bottom: 10px;'>Method 1: Header Authentication (Recommended)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import requests

# Unified token status endpoint (JSON response)
url = "{bearer_status_url}"
headers = {{
    '{header_name}': '{header_value}'
}}

response = requests.get(url, headers=headers)
print(f"Status: {{response.status_code}}")

# JSON response with comprehensive token info
if response.status_code == 200:
    token_info = response.json()
    print("✅ Authentication successful!")
    print(f"Token status: {{token_info['status']}}")
    print(f"Token name: {{token_info['token']['name']}}")
    print(f"User: {{token_info['token']['user']}}")
    if 'expires' in token_info['token']:
        print(f"Expires: {{token_info['token']['expires']}}")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: URL Parameter (Less Secure)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; overflow-x: auto;'><code style='color: #333;'>import requests

# ⚠️  Note: URL parameters are less secure (visible in logs)
url = "{bearer_status_url}"
params = {{
    'access_token': '{token_value}'
}}

response = requests.get(url, params=params)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 3: POST Request Example</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4caf50; overflow-x: auto;'><code style='color: #333;'>import requests
import json

# For your actual API endpoints
url = "{_base_url}/your/api/endpoint"
headers = {{
    '{header_name}': '{header_value}',
    'Content-Type': 'application/json'
}}

data = {{
    'operation': 'example',
    'parameters': {{
        'key1': 'value1',
        'key2': 'value2'
    }}
}}

response = requests.post(url, headers=headers, json=data)
if response.status_code == 200:
    result = response.json()
    print(f"Success: {{result}}")
else:
    print(f"Error: {{response.status_code}} - {{response.text}}")</code></pre>

                    <div style='margin-top: 30px; padding: 15px; background: #e8f5e8; border-radius: 5px; border-left: 4px solid #4caf50;'>
                        <h4 style='color: #2e7d32; margin-bottom: 10px;'>💡 Tips for Production Use</h4>
                        <ul style='color: #2e7d32; margin: 0; padding-left: 20px;'>
                            <li>Always use HTTPS in production</li>
                            <li>Store tokens securely (environment variables, not in code)</li>
                            <li>Set appropriate token expiration dates</li>
                            <li>Monitor token usage in security logs</li>
                            <li>Implement proper error handling</li>
                            <li>Consider rate limiting in your client code</li>
                            <li>Rotate tokens regularly</li>
                            <li>Prefer custom headers over URL parameters</li>
                            <li>Use GitLab personal access tokens for GitLab API integration</li>
                        </ul>
                    </div>
                    </div>
                    """
                    record.python_examples = examples_html
            else:
                super().compute__python_examples()