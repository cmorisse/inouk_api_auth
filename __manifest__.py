# -*- coding: utf-8 -*-
# noinspection PyStatementEffect
{
    'name': "Inouk API Auth",

    'summary': """ Manages authorization and authentication tokens for Odoo API Controllers.""",

    'description': """System automation platform.""",

    'author': "Cyril MORISSE",
    'website': "http://twitter.com/cmorisse",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/master/openerp/addons/base/module/module_data.xml
    # for the full list
    'category': 'Inouk',
    'version': '0.0',
    "license": "LGPL-3",
    # any module necessary for this one to work correctly
    'depends': [
        'inouk_core'
    ],

    # always loaded
    'data': [
        # data
        #'data/mpy_template-ssh-tunnel.xml',
        #'data/ir_sequence.xml',

        # Web clients
        #'views/web_assets_loader.xml',

        # Security objects first as other objects use them
        'security/ir.model.access.csv',
        #'security/groups.xml',
        #'security/ir_rule.xml',

        # Wizards (defined before views that referenced them)
        #'wizards/launch_task_wizard_view.xml',

        # views
        'views/api_auth_token_views.xml',


        # reports
        #'reports/budget_monitoring_report.xml',

        # menus: after views and wizards
        'menu.xml',

        # automated configuration
        #'configuration/configuration.xml',

    ],
    # only loaded in demonstration mode
    'demo': [
        #'demo_data/demo.xml',
    ],
    'application': True,
    'auto_install': False,
    'installable': True,
    #'post_load': 'install_monkey_patches',
}
