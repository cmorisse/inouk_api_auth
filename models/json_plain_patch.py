"""
Plain JSON Patch for Odoo 18

Monkey-patches JsonRPCDispatcher to support plain JSON (non-JSON-RPC) requests/responses
for routes decorated with ik_plain_json=True.

Migration from Odoo 13 to 18:
- JsonRequest class → JsonRPCDispatcher class
- dispatch(self) → dispatch(self, endpoint, args)
- _call_function removed (merged into dispatch logic)
"""

import json
import logging
from odoo import http
from odoo.http import Response
from odoo.tools import date_utils
from werkzeug.exceptions import HTTPException

_logger = logging.getLogger(__name__)

# In Odoo 18, JsonRPCDispatcher is the class handling type='json' routes
# (In Odoo 13, it was called JsonRequest)
JsonRPCDispatcher = http.JsonRPCDispatcher

# Store original dispatch method
_original_dispatch = JsonRPCDispatcher.dispatch


def patched_dispatch(self, endpoint, args):
    """
    Patched dispatch to handle plain JSON requests/responses for ik_plain_json routes.

    For routes with ik_plain_json=True:
    - Request: Accepts plain JSON body (no JSON-RPC wrapper with "jsonrpc", "method", "params")
    - Response: Returns plain JSON (no JSON-RPC wrapper with "jsonrpc", "result")

    For normal routes (ik_plain_json=False or not set):
    - Falls back to standard JSON-RPC 2.0 behavior

    Args:
        endpoint: The route endpoint function to call
        args: URL path arguments from routing
    """

    # Check if this endpoint wants plain JSON (no JSON-RPC wrapper)
    if hasattr(endpoint, 'routing') and endpoint.routing.get('ik_plain_json'):

        _logger.debug(f"Plain JSON mode for {self.request.httprequest.path}")

        try:
            # 1. Parse plain JSON body (without expecting JSON-RPC wrapper)
            try:
                json_data = self.request.get_json_data()

                # For plain JSON, the entire body IS the params (not wrapped in "params" key)
                if isinstance(json_data, dict):
                    self.request.params = dict(json_data, **args)
                else:
                    # If it's not a dict, treat as empty params
                    self.request.params = args

                _logger.debug(f"Plain JSON params: {list(self.request.params.keys())}")

            except (ValueError, AttributeError) as e:
                _logger.warning(f"Invalid JSON data for plain JSON route: {e}")
                # Return plain JSON error (not JSON-RPC wrapped)
                error_response = {'error': 'Invalid JSON data', 'status': 'error'}
                body = json.dumps(error_response)
                return Response(body, status=400, headers=[
                    ('Content-Type', 'application/json'),
                    ('Content-Length', str(len(body)))
                ])

            # 2. Call the endpoint
            if self.request.db:
                result = self.request.registry['ir.http']._dispatch(endpoint)
            else:
                result = endpoint(**self.request.params)

            # 3. Return plain JSON response (no JSON-RPC wrapper)

            # If it's already a Response object, return as-is
            if isinstance(result, Response):
                return result

            # Serialize result to plain JSON
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
            # Handle errors with plain JSON (not JSON-RPC error format)
            _logger.exception("Exception during plain JSON request handling")

            error_message = str(e)
            if hasattr(e, 'name'):
                error_message = e.name

            error_response = {'error': error_message, 'status': 'error'}
            body = json.dumps(error_response)

            # Determine HTTP status code
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
    return _original_dispatch(self, endpoint, args)


# Apply the monkey-patch
JsonRPCDispatcher.dispatch = patched_dispatch
_logger.info("JsonRPCDispatcher monkey-patched for plain JSON support (Odoo 18)")
