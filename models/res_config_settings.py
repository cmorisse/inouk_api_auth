from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    oauth_token_cleanup_delay_hours = fields.Integer(
        string="OAuth Token Retention (hours)",
        config_parameter='inouk_api_auth.oauth_token_cleanup_delay_hours',
        default=168,
        help="Number of hours to keep expired OAuth tokens for auditing before deletion"
    )
