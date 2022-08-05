import logging
import secrets
from datetime import datetime, timedelta
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

from ..controllers.auth import TEST_CONTROLLER_URL

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('bearer', "Bearer"),
    ('xgitlabtoken', "X-Gitlab-Token"),
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

    hello_curl = fields.Char(
        string="Test URL",
        compute="compute__test_curl",
        help="This cURL calls a test controller that just returns the token used."
    )
    hello_url = fields.Char(
        string="Hello URL",
        compute="compute__test_curl",
        help="This is a test cURL that just returns the token used"
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
                    record.hello_curl = f"curl --header 'Authorization: Bearer {record.static_token}' {record.hello_url}"
                elif record.token_type == 'xgitlabtoken':
                    record.hello_curl = f"curl --header 'X-Gitlab-Token: {record.static_token}' {record.hello_url}"
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

    def btn_regenerate_token(self):
        self.token = secrets.token_hex(30)

    def btn_refresh(self):
        pass    
    
    def btn_restore_token(self):
        self.ensure_one()
        self.restore_token()

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