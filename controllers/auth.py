import json
import functools
import timeit
import datetime
import re
import pprint
import logging
import werkzeug.wrappers

from odoo import fields
from odoo.http import Response, request, route, Controller, AuthenticationError
from odoo.tools.safe_eval import safe_eval

#from odoo.addons.muppy_core.api import MpyException, MpyAPIException, mpy_execute
#from odoo.addons.muppy_postgresql_base.scripts import postgresql
#from odoo.addons.muppy_postgresql_replication.scripts import postgresql_sr
#from odoo.addons.muppy_core.scripts import demo
#from odoo.addons.muppy_core.utils import json_datetime_serializer


_logger = logging.getLogger(__name__)

from ..api import ik_authorize

TEST_CONTROLLER_URL = '/inouk/api_auth/v1/hello'
# Base URL for unified token status endpoints
TOKEN_STATUS_CONTROLLER_URL = '/inouk/api_auth/v2/token/status'

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

    @route(TOKEN_STATUS_CONTROLLER_URL + '/bearer', methods=['GET'], type='http', auth='ik_bearer', csrf=False, save_session=False)
    def token_status_bearer(self, *args, **kwargs):
        """Token status for Bearer/X-Gitlab-Token authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    @route(TOKEN_STATUS_CONTROLLER_URL + '/awssigv4', methods=['GET'], type='http', auth='ik_awssigv4', csrf=False, save_session=False)
    def token_status_awssigv4(self, *args, **kwargs):
        """Token status for AWS SigV4 authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    @route(TOKEN_STATUS_CONTROLLER_URL + '/httpbasic', methods=['GET'], type='http', auth='ik_httpbasicauth', csrf=False, save_session=False)
    def token_status_httpbasic(self, *args, **kwargs):
        """Token status for HTTP Basic authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    def _token_status_unified(self, *args, **kwargs):
        """ Unified token status checker for all authentication methods.

        Returns comprehensive token information in JSON format.
        Supports all authentication methods: Bearer, AWS SigV4, HTTP Basic.
        """
        _logger.info("Token status check - received args: %s", args)
        _logger.info("Token status check - received kwargs: %s", kwargs)

        # Get auth context created by authentication method
        auth_context = getattr(request, 'inouk_api_auth', None)
        if not auth_context:
            return {
                'error': 'Authentication failed',
                'message': 'No valid authentication context found',
                'status': 'failed'
            }

        try:
            return {
                'status': self._get_token_status_from_context(auth_context),
                'token': self._get_token_info_from_context(auth_context),
                'auth_method': self._get_auth_method_from_context(auth_context),
                'request_info': self._get_request_info_from_context(auth_context)
            }
        except Exception as e:
            _logger.error("Error generating token status: %s", e)
            return {
                'error': 'Internal error',
                'message': 'Failed to generate token status',
                'status': 'error'
            }

    def _get_token_status_from_context(self, auth_context):
        """Get overall token status from auth context"""
        if auth_context.get('is_compromised'):
            return 'compromised'
        elif auth_context.get('is_expired'):
            return 'expired'
        else:
            return 'active'

    def _get_token_info_from_context(self, auth_context):
        """Get safe token information from auth context"""
        token_obj = auth_context.get('token')
        if not token_obj:
            return {}

        token_info = {
            'name': auth_context.get('token_name'),
            'type': auth_context.get('token_type'),
            'user': auth_context.get('user_name'),
            'created': token_obj.create_date.isoformat() if token_obj.create_date else None,
            'is_compromised': auth_context.get('is_compromised'),
            'enforce_https': auth_context.get('enforce_integrity'),
            'description': token_obj.description or None
        }

        # Add expiration info if set
        if token_obj.expiration_ts:
            token_info['expires'] = token_obj.expiration_ts.isoformat()
            now = fields.Datetime.now()
            if token_obj.expiration_ts > now:
                delta = token_obj.expiration_ts - now
                token_info['expires_in_days'] = delta.days
                token_info['expires_in_hours'] = delta.total_seconds() / 3600
            else:
                token_info['expires_in_days'] = 0
                token_info['expires_in_hours'] = 0

        return token_info

    def _get_auth_method_from_context(self, auth_context):
        """Get authentication method specific information from auth context"""
        auth_details = auth_context.get('auth_details', {})
        token_type = auth_context.get('token_type')

        auth_info = {'type': token_type}

        if token_type == 'awssigv4':
            auth_info.update({
                'access_key_id': auth_details.get('access_key_id'),
                'region': auth_details.get('region', 'N/A'),
                'service': auth_details.get('service', 'N/A'),
                'algorithm': auth_details.get('algorithm')
            })
        elif token_type == 'httpbasicauth':
            auth_info.update({
                'username': auth_details.get('username'),
                'encoding': auth_details.get('encoding')
            })
        elif token_type in ['bearer', 'xgitlabtoken']:
            auth_info.update({
                'header_type': auth_details.get('header_type'),
                'token_source': auth_details.get('token_source')
            })

        return auth_info

    def _get_request_info_from_context(self, auth_context):
        """Get safe request information from auth context"""
        request_source = auth_context.get('request_source', {})

        return {
            'authenticated_at': auth_context.get('authenticated_at'),
            'remote_ip': request_source.get('remote_ip', 'unknown'),
            'via': request_source.get('via'),
            'proxy_chain': request_source.get('proxy_chain', []),
            'proxy_type': request_source.get('proxy_type'),
            'using_https': request_source.get('is_https'),
            'user_agent': request_source.get('user_agent', 'unknown'),
            'referer': request_source.get('referer')
        }

