import logging
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

from ..controllers.auth import TEST_CONTROLLER_URL, TEST_CONTROLLER_V2_URL, AWSSIGV4_TEST_CONTROLLER_URL
from .awssigv4_helper import generate_aws_credentials, generate_signed_curl_command

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('bearer', "Bearer"),
    ('xgitlabtoken', "X-Gitlab-Token"),
    ('awssigv4', "AWS Signature V4"),
]



class InoukAPIAuthToken(models.Model):
    _name = 'ik.api_auth_token'
    _description = "API Auth Token - Inouk"
    
    name = fields.Char(required=True)
    static_token = fields.Char(required=True, index=True)
    description = fields.Char()
    user_id = fields.Many2one('res.users', required=True)
    token_type = fields.Selection(
        selection=TOKEN_TYPES_LIST, 
        string="Type",
        required=True,
        default="bearer"
    )
    expiration_ts = fields.Datetime(
        string="Expires on",
        help="You can define a timestamp after which the token will expire. "
    )
    enforce_integrity = fields.Boolean(
        default=True,
        help="When checked, Muppy will expires Token if received over http (not https)."
    )
    is_compromised = fields.Boolean(
        help="Muppy can set tokens as compromised. Eg. they have been sent using http and not https.",
        default=False
    )
    security_log = fields.Text()

    # AWS SigV4 specific fields
    awssigv4_access_key_id = fields.Char(
        string="AWS Access Key ID",
        help="AWS Access Key ID for Signature Version 4 authentication (format: AKIA...)"
    )
    awssigv4_secret_access_key = fields.Char(
        string="AWS Secret Access Key",
        help="AWS Secret Access Key for Signature Version 4 authentication (40 characters)"
    )

    hello_curl = fields.Char(
        string="Test URL",
        compute="compute__test_curl",
        help="This cURL calls a test controller that just returns the token used."
    )
    test_use_header = fields.Boolean(
        "Token in header",
        default=True
    )
    hello_url = fields.Char(
        string="Hello URL",
        compute="compute__test_curl",
        help="This is a test cURL that just returns the token used"
    )
    python_examples = fields.Html(
        string="Python Examples",
        compute="compute__python_examples",
        help="Python requests examples for this authentication token"
    )
    def compute__test_curl(self):
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if _base_url:
                record.hello_url = urljoin(
                    _base_url,
                    TEST_CONTROLLER_URL
                )
                if record.token_type == 'bearer':
                    if record.test_use_header:
                        record.hello_curl = f"curl --header 'Authorization: Bearer {record.static_token}' {record.hello_url}"
                    else:
                        record.hello_curl = f"curl '{record.hello_url}?access_token={record.static_token}'"

                elif record.token_type == 'xgitlabtoken':
                    if record.test_use_header:
                        record.hello_curl = f"curl --header 'X-Gitlab-Token: {record.static_token}' {record.hello_url}"
                    else:
                        record.hello_curl = f"curl '{record.hello_url}?access_token={record.static_token}'"

                elif record.token_type == 'awssigv4':
                    record.hello_curl = record.compute__awssigv4_test_curl()

                else:
                    raise UserError("Unsupported token_type: %s" %  record.token_type)
            else:
                record.hello_url = None

    _sql_constraints = [
        ('token_uniq', "UNIQUE(static_token, token_type)", "Token must be unique!")
    ]

    @api.model
    def default_get(self, fields_list):
        result = super().default_get(fields_list)
        if 'static_token' in fields_list:
            result['static_token'] = secrets.token_hex(30)
        return result

    def btn_regenerate_credentials(self):
        """Regenerate token or credentials based on token type"""
        self.ensure_one()

        if self.token_type in ['bearer', 'xgitlabtoken']:
            # Generate standard hex token
            self.static_token = secrets.token_hex(30)
        elif self.token_type == 'awssigv4':
            # Generate AWS credentials
            access_key_id, secret_access_key = generate_aws_credentials()
            self.write({
                'awssigv4_access_key_id': access_key_id,
                'awssigv4_secret_access_key': secret_access_key,
            })

    def btn_refresh(self):
        pass

    def btn_restore_token(self):
        self.ensure_one()
        self.restore_token()

    def compute__awssigv4_test_curl(self):
        """Generate AWS SigV4 signed curl command for testing"""
        self.ensure_one()
        if not self.awssigv4_access_key_id or not self.awssigv4_secret_access_key:
            return "# Generate AWS keys first"

        # Use AWS SigV4 specific URL
        _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        if not _base_url:
            return "# Configure web.base.url first"

        awssigv4_url = urljoin(_base_url, AWSSIGV4_TEST_CONTROLLER_URL)

        return generate_signed_curl_command(
            url=awssigv4_url,
            access_key_id=self.awssigv4_access_key_id,
            secret_access_key=self.awssigv4_secret_access_key,
            region='us-east-1',  # Default region
            service='execute-api'  # Default service
        )

    def compute__python_examples(self):
        """Generate Python requests examples for all authentication methods"""
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if not _base_url:
                record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
                continue

            # Generate URLs for different endpoints
            hello_v1_url = urljoin(_base_url, TEST_CONTROLLER_URL)
            hello_v2_url = urljoin(_base_url, TEST_CONTROLLER_V2_URL)
            awssigv4_url = urljoin(_base_url, AWSSIGV4_TEST_CONTROLLER_URL)

            examples_html = "<div style='padding: 10px; font-family: monospace;'>"

            if record.token_type in ['bearer', 'xgitlabtoken']:
                token_value = record.static_token or 'YOUR_TOKEN_HERE'

                if record.token_type == 'bearer':
                    header_name = 'Authorization'
                    header_value = f'Bearer {token_value}'
                    title = "Bearer Token Authentication"
                else:  # xgitlabtoken
                    header_name = 'X-Gitlab-Token'
                    header_value = token_value
                    title = "X-Gitlab-Token Authentication"

                examples_html += f"""
                <h3 style='color: #2e7bcf; margin-bottom: 15px;'>{title}</h3>

                <h4 style='color: #666; margin-bottom: 10px;'>Method 1: Header Authentication (Recommended)</h4>
                <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import requests

# Test endpoint (v2 - recommended)
url = "{hello_v2_url}"
headers = {{
    '{header_name}': '{header_value}'
}}

response = requests.get(url, headers=headers)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text}}")

# Error handling
if response.status_code == 200:
    print("✅ Authentication successful!")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: URL Parameter (Less Secure)</h4>
                <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; overflow-x: auto;'><code style='color: #333;'>import requests

# ⚠️  Note: URL parameters are less secure (visible in logs)
url = "{hello_v2_url}"
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
    'key': 'value',
    'another_key': 'another_value'
}}

response = requests.post(url, headers=headers, json=data)
if response.status_code == 200:
    result = response.json()
    print(f"Success: {{result}}")
else:
    print(f"Error: {{response.status_code}} - {{response.text}}")</code></pre>
                """

            elif record.token_type == 'awssigv4':
                if not record.awssigv4_access_key_id or not record.awssigv4_secret_access_key:
                    examples_html += "<div style='padding: 20px; color: #ff9800;'><i>Generate AWS keys first to see examples</i></div>"
                else:
                    access_key = record.awssigv4_access_key_id
                    secret_key = record.awssigv4_secret_access_key

                    examples_html += f"""
                    <h3 style='color: #2e7bcf; margin-bottom: 15px;'>AWS Signature Version 4 Authentication</h3>

                    <h4 style='color: #666; margin-bottom: 10px;'>Installation Required</h4>
                    <pre style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; overflow-x: auto;'><code style='color: #333;'># Install required package
pip install requests-aws4auth</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 1: Using requests-aws4auth Library</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import requests
from requests_aws4auth import AWS4Auth

# AWS Credentials
access_key_id = '{access_key}'
secret_access_key = '{secret_key}'
region = 'us-east-1'  # You can change this
service = 'execute-api'  # You can change this

# Create auth object
auth = AWS4Auth(access_key_id, secret_access_key, region, service)

# Test endpoint
url = "{awssigv4_url}"
response = requests.get(url, auth=auth)

print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text}}")

if response.status_code == 200:
    print("✅ AWS SigV4 authentication successful!")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: POST Request with JSON Data</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4caf50; overflow-x: auto;'><code style='color: #333;'>import requests
import json
from requests_aws4auth import AWS4Auth

# Setup authentication
auth = AWS4Auth('{access_key}', '{secret_key}', 'us-east-1', 'execute-api')

# Your API endpoint
url = "{_base_url}/your/api/endpoint"
headers = {{
    'Content-Type': 'application/json'
}}

data = {{
    'operation': 'example',
    'parameters': {{
        'key1': 'value1',
        'key2': 'value2'
    }}
}}

response = requests.post(url, auth=auth, headers=headers, json=data)
if response.status_code == 200:
    result = response.json()
    print(f"Success: {{result}}")
else:
    print(f"Error: {{response.status_code}} - {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 3: Manual Signature (Advanced)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #9c27b0; overflow-x: auto;'><code style='color: #333;'># For advanced users who want to implement signing manually
# This is automatically handled by requests-aws4auth library
# See AWS SigV4 documentation for manual implementation details

# Current auto-generated signed curl command:
# {record.hello_curl if hasattr(record, 'hello_curl') else 'Generate AWS keys to see curl example'}</code></pre>
                    """

            examples_html += """
            <div style='margin-top: 30px; padding: 15px; background: #e8f5e8; border-radius: 5px; border-left: 4px solid #4caf50;'>
                <h4 style='color: #2e7d32; margin-bottom: 10px;'>💡 Tips for Production Use</h4>
                <ul style='color: #2e7d32; margin: 0; padding-left: 20px;'>
                    <li>Always use HTTPS in production</li>
                    <li>Store tokens securely (environment variables, not in code)</li>
                    <li>Set appropriate token expiration dates</li>
                    <li>Monitor token usage in security logs</li>
                    <li>Implement proper error handling</li>
                    <li>Consider rate limiting in your client code</li>
                </ul>
            </div>
            """

            examples_html += "</div>"
            record.python_examples = examples_html

    def restore_token(self):
        for record in self:
            record.write({
                'is_compromised': False,
                'expiration_ts': None,
                'security_log': "%s: Token re-enabled by %s\n%s" % (
                    fields.Datetime.now().isoformat(),
                    record.env.user.name,
                    record.security_log or ''
                )
            })