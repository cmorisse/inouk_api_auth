# -*- coding: utf-8 -*-
{
    'name': 'Inouk API Auth',
    'summary': ' Manages authorization and authentication tokens for Odoo API Controllers.',
    'description': 'System automation platform.',
    'author': 'Cyril MORISSE',
    'website': 'http://twitter.com/cmorisse',
    'category': 'Inouk',
    'version': '0.0',
    'license': 'LGPL-3',
    'depends': ['inouk_core'],
    'data': [
        'security/ir.model.access.csv',
        'views/api_auth_token_views.xml',
        'menu.xml'
    ],
    'demo': [],
    'application': True,
    'auto_install': False,
    'installable': True
}
