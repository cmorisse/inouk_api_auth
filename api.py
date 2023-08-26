import json
import functools
import timeit
import datetime
import re
import pprint
import logging
import werkzeug.wrappers
from urllib.parse import urlparse

from odoo import fields
from odoo.http import request, route, Controller, AuthenticationError
from odoo.tools.safe_eval import safe_eval



_logger = logging.getLogger(__name__)



def ik_authorize(func):
    """ Bearer Token https://tools.ietf.org/html/rfc6750 compatible
    https://stackoverflow.com/questions/22229996/basic-http-and-bearer-token-authentication

    Bearer Token can be passed using:
      - Authorization header
      - access_token URL parameter 
      
    For compatibility with Gitlab WebHook, ik_authorize accepts:
      - X-Gitlab-Token header

    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):

        # Check Sender for token auth
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')
        _logger.debug("HTTP_REFERER = %s", http_referer)
        requested_url = request.httprequest.url
        _up = urlparse(requested_url)
        _rp = urlparse(http_referer)
        if _up.scheme != 'https' or (http_referer and _rp.scheme != 'https'):
            is_compromised = True
        else:
            is_compromised = False

        token_string = request.httprequest.headers.get('Authorization')
        if token_string:
            token_type = 'bearer'
            _logger.info("Received header 'Authorization: %s'", token_string)

        else:
            token_string = request.httprequest.headers.get('X-Gitlab-Token')
            if token_string:
                token_type = 'xgitlabtoken'
                _logger.info("Received header 'X-Gitlab-Token: %s'", token_string)

            else:
                token_string = request.params.get('access_token')
                if not token_string:
                    token_string = request.httprequest.args.get('access_token')

                if token_string: 
                    if 'access_token' in request.params:
                        del request.params['access_token']
                    token_type = 'bearer'
                else:
                    raise AuthenticationError("Missing required Authorization.")

        if token_string.lower().startswith('bearer '):
            static_token = token_string.split()[1]
        else:
            static_token = token_string.strip()

        token_obj = request.env['ik.api_auth_token'].sudo().search(
            [
                ('static_token', '=', static_token),
                ('token_type', '=', token_type),
                ('is_compromised', '=', False),
                '|',
                    ('expiration_ts', '=', False),
                    ('expiration_ts', '>', fields.Datetime.now()),
            ],
            order='id DESC', 
            limit=1
        )            
        if not token_obj:
            raise AuthenticationError("Invalid Access Token.")

        if is_compromised:
            if token_obj.enforce_integrity:
                token_obj.write({
                    'is_compromised': True,
                    'expiration_ts': fields.Datetime.now(),
                    'security_log': ("%s: Token expired by Muppy since it has been received over "
                                    "'http' from %s.\n%s") % (
                                        fields.Datetime.now().isoformat(),
                                        sender_ip,
                                        token_obj.security_log or ''
                                    )
                })
                token_obj.flush() ; request.env.cr.commit()
                _logger.info("Token %s set as compromised !", token_obj)
                raise AuthenticationError("Invalid Access Token.")
            else:
                _logger.warning("Token %s received over unsecure 'http' from %s.", token_obj, sender_ip)
        user_obj = token_obj.user_id
        #request.session.uid = static_token_obj.user_id.id
        #request.uid = static_token_obj.user_id.id
        request.session.uid = user_obj.id
        request.uid = user_obj.id
        request.session.session_token = user_obj._compute_session_token(request.session.sid)
        #request.inouk_api_auth_token_id = token_obj.id
        kwargs['token_obj'] = token_obj
        return func(self, *args, **kwargs)
    return wrapper

