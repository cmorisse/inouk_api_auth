import json
import logging
from odoo.http import JsonRequest, Response
from odoo.tools import date_utils
from werkzeug.exceptions import HTTPException

_logger = logging.getLogger(__name__)

# Store original methods
_original_dispatch = JsonRequest.dispatch
_original_call_function = JsonRequest._call_function

def patched_call_function(self, *args, **kwargs):
    """Patched _call_function to use plain JSON as params for ik_plain_json routes"""

    # For plain JSON routes, use the entire JSON request as params
    if hasattr(self, 'endpoint') and self.endpoint and \
       hasattr(self.endpoint, 'routing') and \
       self.endpoint.routing.get('ik_plain_json'):

        # Replace empty params with the actual JSON body
        if not kwargs and hasattr(self, 'jsonrequest') and isinstance(self.jsonrequest, dict):
            # For plain JSON, the entire request body IS the params
            kwargs = self.jsonrequest
            _logger.debug(f"Using plain JSON as params for {self.httprequest.path}: {list(kwargs.keys())}")

    # Call original with potentially modified kwargs
    return _original_call_function(self, *args, **kwargs)

def patched_dispatch(self):
    """Patched dispatch to handle plain JSON responses"""

    # Check if this endpoint wants plain JSON (no JSON-RPC wrapper)
    if hasattr(self, 'endpoint') and self.endpoint and \
       hasattr(self.endpoint, 'routing') and \
       self.endpoint.routing.get('ik_plain_json'):

        _logger.debug(f"Plain JSON response for {self.httprequest.path}")

        # Call the controller method
        try:
            result = self._call_function(**self.params)

            # If it's already a Response, return as-is
            if isinstance(result, Response):
                return result

            # Return plain JSON without JSON-RPC wrapper
            body = json.dumps(result, default=date_utils.json_default)
            return Response(
                body,
                status=200,
                headers=[
                    ('Content-Type', 'application/json'),
                    ('Content-Length', str(len(body)))
                ]
            )
        except Exception as e:
            # Handle errors with plain JSON
            _logger.exception("Exception during plain JSON request handling")

            error_message = str(e)
            if hasattr(e, 'name'):
                error_message = e.name

            error_response = {'error': error_message, 'status': 'error'}
            body = json.dumps(error_response)

            # Determine status code
            status = 500
            if isinstance(e, HTTPException):
                status = e.code
            elif hasattr(e, 'status_code'):
                status = e.status_code

            return Response(
                body,
                status=status,
                headers=[
                    ('Content-Type', 'application/json'),
                    ('Content-Length', str(len(body)))
                ]
            )

    # Default JSON-RPC behavior for normal routes
    return _original_dispatch(self)

# Apply the monkey-patches
JsonRequest._call_function = patched_call_function
JsonRequest.dispatch = patched_dispatch
_logger.info("JsonRequest monkey-patched for plain JSON support (_call_function and dispatch)")