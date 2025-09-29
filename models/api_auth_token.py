import logging
from datetime import datetime, timedelta
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

from ..controllers.auth import TEST_CONTROLLER_URL, TEST_CONTROLLER_V2_URL

_logger = logging.getLogger(__name__)


# Base token types - specific types are added via inheritance
TOKEN_TYPES_LIST = []


class InoukAPIAuthToken(models.Model):
    _name = 'ik.api_auth_token'
    _description = "API Auth Token - Inouk"

    name = fields.Char(required=True)
    static_token = fields.Char(index=True)
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

    # Type-specific fields are added via inheritance in separate files

    test_use_header = fields.Boolean(
        "Token in header",
        default=True
    )
    hello_url = fields.Char(
        string="Hello URL",
        compute="compute__test_curl",
        help="This is a test cURL that just returns the token used"
    )
    hello_curl = fields.Char(
        string="Hello cURL",
        compute="compute__test_curl",
        help="This is a test cURL that just returns the token used"
    )
    python_examples = fields.Html(
        string="Python Examples",
        compute="compute__python_examples",
        help="Python requests examples for this authentication token"
    )

    def compute__test_curl(self):
        """Base cURL computation - overridden by type-specific implementations"""
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if _base_url:
                record.hello_url = urljoin(
                    _base_url,
                    TEST_CONTROLLER_URL
                )
                # Default fallback - should be overridden by inherited models
                record.hello_curl = f"# Generate credentials first for {record.token_type}"
            else:
                record.hello_url = None
                record.hello_curl = "# Configure web.base.url first"

    _sql_constraints = [
        ('token_uniq', "UNIQUE(static_token, token_type)", "Token must be unique!")
    ]

    @api.model
    def default_get(self, fields_list):
        """Set default values - static_token generation moved to type-specific implementations"""
        result = super().default_get(fields_list)
        # static_token defaults are handled by inherited models based on token_type
        return result

    def btn_regenerate_credentials(self):
        """Base regenerate credentials method - overridden by type-specific implementations"""
        self.ensure_one()
        # Default implementation - should be overridden by inherited models
        raise UserError(_("Credential regeneration not implemented for token type: %s") % self.token_type)

    def btn_refresh(self):
        pass

    def btn_restore_token(self):
        self.ensure_one()
        self.restore_token()

    # Type-specific test curl methods moved to inherited files

    # Type-specific compute methods moved to inherited files

    def compute__python_examples(self):
        """Base Python examples computation - overridden by type-specific implementations"""
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if not _base_url:
                record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
            else:
                # Default fallback - should be overridden by inherited models
                record.python_examples = f"<div style='padding: 20px; color: #ff9800;'><i>Generate credentials first for {record.token_type}</i></div>"

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