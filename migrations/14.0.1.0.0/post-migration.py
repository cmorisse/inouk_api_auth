import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Migrate existing bearer and xgitlabtoken tokens to new flexible header system

    This migration:
    1. Updates existing bearer tokens to use header type with Authorization/Bearer config
    2. Updates existing xgitlabtoken tokens to use header type with X-Gitlab-Token config
    3. Sets appropriate defaults for all new fields
    4. Logs the migration results
    """
    _logger.info("Starting inouk_api_auth token migration to flexible header system...")

    try:
        # Migrate bearer tokens to new header system
        cr.execute("""
            UPDATE ik_api_auth_token
            SET token_type = 'header',
                header_name = 'Authorization',
                header_prefix = 'Bearer ',
                actual_header_name = 'Authorization',
                actual_header_prefix = 'Bearer ',
                support_url_param = true,
                url_param_name = 'access_token',
                actual_url_param_name = 'access_token'
            WHERE token_type = 'bearer'
        """)

        bearer_count = cr.rowcount
        _logger.info("Migrated %d bearer tokens to flexible header system", bearer_count)

        # Migrate xgitlabtoken tokens to new header system
        cr.execute("""
            UPDATE ik_api_auth_token
            SET token_type = 'header',
                header_name = 'X-Gitlab-Token',
                header_prefix = '',
                actual_header_name = 'X-Gitlab-Token',
                actual_header_prefix = '',
                support_url_param = true,
                url_param_name = 'access_token',
                actual_url_param_name = 'access_token'
            WHERE token_type = 'xgitlabtoken'
        """)

        gitlab_count = cr.rowcount
        _logger.info("Migrated %d X-Gitlab-Token tokens to flexible header system", gitlab_count)

        # Update any remaining header tokens to have proper defaults
        cr.execute("""
            UPDATE ik_api_auth_token
            SET header_name = COALESCE(header_name, 'Authorization'),
                header_prefix = COALESCE(header_prefix, 'Bearer '),
                actual_header_name = COALESCE(actual_header_name, header_name, 'Authorization'),
                actual_header_prefix = COALESCE(actual_header_prefix, header_prefix, 'Bearer '),
                support_url_param = COALESCE(support_url_param, true),
                url_param_name = COALESCE(url_param_name, 'access_token'),
                actual_url_param_name = COALESCE(actual_url_param_name, url_param_name, 'access_token')
            WHERE token_type = 'header'
              AND (header_name IS NULL
                   OR actual_header_name IS NULL
                   OR actual_url_param_name IS NULL)
        """)

        defaults_count = cr.rowcount
        _logger.info("Applied defaults to %d existing header tokens", defaults_count)

        # Get final counts for reporting
        cr.execute("SELECT COUNT(*) FROM ik_api_auth_token WHERE token_type = 'header'")
        total_header_tokens = cr.fetchone()[0]

        cr.execute("SELECT COUNT(*) FROM ik_api_auth_token WHERE token_type IN ('bearer', 'xgitlabtoken')")
        remaining_legacy_tokens = cr.fetchone()[0]

        _logger.info("Migration completed successfully!")
        _logger.info("- Total header tokens: %d", total_header_tokens)
        _logger.info("- Remaining legacy tokens: %d", remaining_legacy_tokens)

        if remaining_legacy_tokens > 0:
            _logger.warning(
                "Found %d tokens with legacy types (bearer/xgitlabtoken). "
                "These may have been created during migration or have custom configurations. "
                "They will continue to work but consider updating them to use the new header type.",
                remaining_legacy_tokens
            )

        # Log completion message
        _logger.info("""
========================================
inouk_api_auth Migration Complete
========================================
Bearer and X-Gitlab-Token types have been
migrated to the new flexible header system.

Your existing tokens will continue working
with the same authentication behavior.

For new tokens, use 'Header-Based Token' type
for maximum flexibility and configuration options.
========================================
        """)

    except Exception as e:
        _logger.error("Error during token migration: %s", str(e))
        _logger.error("Migration failed - tokens may need manual review")
        raise

    return True