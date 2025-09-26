import json
import functools
import timeit
import datetime
import re
import pprint
import logging
import werkzeug.wrappers

from odoo.http import request, route, Controller, AuthenticationError
from odoo.tools.safe_eval import safe_eval

#from odoo.addons.muppy_core.api import MpyException, MpyAPIException, mpy_execute
#from odoo.addons.muppy_postgresql_base.scripts import postgresql
#from odoo.addons.muppy_postgresql_replication.scripts import postgresql_sr
#from odoo.addons.muppy_core.scripts import demo
#from odoo.addons.muppy_core.utils import json_datetime_serializer


_logger = logging.getLogger(__name__)

from ..api import ik_authorize

TEST_CONTROLLER_URL = '/inouk/api_auth/v1/hello'
TEST_CONTROLLER_V2_URL = '/inouk/api_auth/v2/hello'

# Important
# All route() must set save_session=False to prevent Odoo from returning a session_id cookie.
#
class InoukAPIAuthControllerV1(Controller):
    """ API to manage inouk_auth_api tokens.
    """
    @ik_authorize
    @route(TEST_CONTROLLER_URL, methods=['GET'], type='http', auth='none', csrf=False, save_session=False)
    def hello(self, *args, **kwargs):
        """ A dump controller to test token using deprecated decorator.
        """
        _logger.info("received args: %s", args )
        _logger.info("received kwargs: %s", kwargs )
        return "Hello ! Call Ok. Received %s\n" % kwargs['token_obj']

    @route(TEST_CONTROLLER_V2_URL, methods=['GET'], type='http', auth='ik_bearer', csrf=False, save_session=False)
    def hello_v2(self, *args, **kwargs):
        """ A controller to test token using new auth='ik_bearer' method.
        """
        _logger.info("received args: %s", args )
        _logger.info("received kwargs: %s", kwargs )

        # Access token object stored by the authentication method
        token_obj = getattr(request, 'inouk_token_obj', None)
        if token_obj:
            return "Hello v2! Call Ok. Received token: %s (User: %s)\n" % (token_obj.name, token_obj.user_id.name)
        else:
            return "Hello v2! Call Ok but no token object found.\n"

