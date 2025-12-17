# -*- coding: utf-8 -*-
import logging

from odoo import models, fields
from odoo.http import request
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class IrHttpGitWebhook(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_ik_gitwebhook(cls):
        """Unified authentication for Git provider webhooks

        Supports:
        - GitLab: X-Gitlab-Token header
        - GitHub: X-Hub-Signature-256 (future: HMAC validation)
        - Standard Bearer token as fallback
        - URL parameter as fallback

        This method replaces the deprecated ik_xgitlabtoken auth method
        and provides a unified way to authenticate webhooks from various
        Git providers (GitLab, GitHub, Azure DevOps, Bitbucket, etc.)
        """
        # Get request information for security checks
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')

        token_string = None
        auth_source = None

        # Priority 1: GitLab webhook token
        gitlab_token = request.httprequest.headers.get('X-Gitlab-Token')
        if gitlab_token:
            token_string = gitlab_token
            auth_source = 'gitlab_webhook'
            _logger.info("Git webhook auth via X-Gitlab-Token header")

        # Priority 2: GitHub webhook signature (future enhancement)
        # github_signature = request.httprequest.headers.get('X-Hub-Signature-256')
        # if github_signature and not token_string:
        #     # TODO: Implement HMAC validation for GitHub
        #     # For now, GitHub can use Bearer tokens
        #     pass

        # Priority 3: Standard Bearer token (works for both GitLab CI and GitHub Actions)
        if not token_string:
            auth_header = request.httprequest.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token_string = auth_header[7:]
                auth_source = 'bearer'
                _logger.info("Git webhook auth via Authorization header")

        # Priority 4: URL parameter (legacy support, Odoo 18: use httprequest.args)
        if not token_string:
            token_string = request.httprequest.args.get('access_token')
            if token_string:
                auth_source = 'url_param'
                _logger.info("Git webhook auth via URL parameter")

        if not token_string:
            raise AccessDenied("Missing webhook authentication token")

        # Search for token - accept multiple types including xgitlabtoken for backward compat
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('static_token', '=', token_string),
            ('token_type', 'in', ['bearer', 'xgitlabtoken', 'header']),
        ], order='id DESC', limit=1)

        # Decision tree based on token status
        if not token_obj:
            _logger.warning("Git webhook authentication failed - no token found")
            raise AccessDenied("Invalid webhook token")
        elif token_obj.is_compromised:
            _logger.warning("Git webhook authentication failed - token %s (ID: %s) is compromised",
                          token_obj.name, token_obj.id)
            raise AccessDenied("Invalid webhook token")
        elif token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("Git webhook authentication failed - token %s (ID: %s) expired at %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts)
            raise AccessDenied("Invalid webhook token")

        # Check if token was sent over HTTPS
        is_compromised = cls._check_token_compromised(request, http_referer)

        if is_compromised:
            if token_obj.enforce_integrity:
                cls._compromise_token(token_obj, sender_ip)
                raise AccessDenied("Invalid webhook token")
            else:
                _logger.warning("Git webhook token %s received over unsecure 'http' from %s.",
                              token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.update_env(user=user_obj.id)

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Store webhook context for controller use
        webhook_provider = cls._detect_webhook_provider(request)
        request.gitwebhook_context = {
            'source': auth_source,
            'provider': webhook_provider,
            'token_type': token_obj.token_type
        }

        # Build auth details specific to Git webhooks
        auth_details = {
            'source': auth_source,
            'provider': webhook_provider,
            'token_type': token_obj.token_type
        }

        # Build and store complete auth context
        request.inouk_api_auth = cls._build_auth_context(
            token_obj=token_obj,
            auth_type='gitwebhook',
            auth_details=auth_details
        )

        # Keep legacy attribute for backward compatibility
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via Git webhook token %s (provider: %s)",
                     user_obj.name, token_obj.name, webhook_provider)

    @classmethod
    def _detect_webhook_provider(cls, request):
        """Detect which Git provider sent the webhook

        Returns:
            str: 'gitlab', 'github', 'azure_devops', 'bitbucket', or 'unknown'
        """
        headers = request.httprequest.headers

        # GitLab webhooks have specific headers
        if 'X-Gitlab-Event' in headers:
            return 'gitlab'

        # GitHub webhooks have specific headers
        if 'X-GitHub-Event' in headers:
            return 'github'

        # Azure DevOps webhooks
        if 'X-VSS-UserAgent' in headers:
            return 'azure_devops'

        # Bitbucket webhooks
        if 'X-Event-Key' in headers and 'X-Hook-UUID' in headers:
            return 'bitbucket'

        # Check for GitLab-specific token header as fallback
        if 'X-Gitlab-Token' in headers:
            return 'gitlab'

        return 'unknown'