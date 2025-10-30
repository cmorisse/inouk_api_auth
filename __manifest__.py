# -*- coding: utf-8 -*-
{
    'name': "Inouk API Auth",

    'summary': """ Manages authorization and authentication tokens for Odoo API Controllers.""",

    'description': """
Token-based API authentication system for Odoo controllers.

Features:
* Flexible Header-Based Token authentication (NEW)
* Bearer Token and X-Gitlab-Token support (legacy compatibility)
* Configurable headers (Authorization, X-API-Key, X-Auth-Token, custom)
* Configurable URL parameters (access_token, api_key, token, custom)
* Service presets for quick setup (OAuth2, GitLab, API Keys)
* HTTPS integrity enforcement
* Token expiration management
* Security audit logging
* New auth='ik_header' authentication method
* Legacy auth='ik_bearer' compatibility
* Legacy @ik_authorize decorator support (deprecated)
""",

    'author': "Cyril MORISSE",
    'website': "http://twitter.com/cmorisse",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/master/openerp/addons/base/module/module_data.xml
    # for the full list
    'category': 'Inouk',
    'version': '1.0.0',
    "license": "LGPL-3",
    # any module necessary for this one to work correctly
    'depends': [
        'inouk_core'
    ],

    # always loaded
    'data': [
        'security/ir.model.access.csv',
        #'security/groups.xml',
        #'security/ir_rule.xml',

        # views
        'views/api_auth_token_views.xml',
        'menu.xml'
    ],
    'demo': [],
    'application': True,
    'auto_install': False,
    'installable': True
}
