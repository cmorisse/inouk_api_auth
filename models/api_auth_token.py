import logging
import secrets
from datetime import datetime, timedelta

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

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