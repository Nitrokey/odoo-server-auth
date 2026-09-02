# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

_logger = logging.getLogger(__name__)


def _column_exists(cr, table, column):
    cr.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_name = %s AND column_name = %s
        """,
        (table, column),
    )
    return bool(cr.fetchone())


def migrate(cr, version):
    """Migrate the single-active-key model to multiple active keys.

    * legacy non-current keys are deleted (they had no usable wrapping)
    * the master key stored on vault.right (column ``key``) is moved to a
      vault.right.key row wrapped with the user's former current key
    * the inbox key stored on vault.inbox (column ``key``) is moved to a
      vault.inbox.wrap row wrapped with the inbox owner's former current key
    """
    if not _column_exists(cr, "res_users_key", "current"):
        _logger.info("vault: nothing to migrate, 'current' column is gone")
        return

    # Delete legacy non-current keys, they were unusable
    cr.execute("DELETE FROM res_users_key WHERE current IS NOT TRUE")
    _logger.info("vault: removed %s legacy non-current keys", cr.rowcount)

    # Move vault.right.key -> vault.right.key model rows
    if _column_exists(cr, "vault_right", "key"):
        cr.execute(
            """
            INSERT INTO vault_right_key (right_id, user_key_id, key)
            SELECT r.id, k.id, r.key
            FROM vault_right r
            JOIN res_users_key k
              ON k.user_id = r.user_id AND k.current IS TRUE
            WHERE r.key IS NOT NULL
            ON CONFLICT (right_id, user_key_id) DO NOTHING
            """
        )
        _logger.info("vault: migrated %s vault right keys", cr.rowcount)

    # Move vault.inbox.key -> vault.inbox.wrap model rows
    if _column_exists(cr, "vault_inbox", "key"):
        cr.execute(
            """
            INSERT INTO vault_inbox_wrap (inbox_id, user_key_id, key)
            SELECT i.id, k.id, i.key
            FROM vault_inbox i
            JOIN res_users_key k
              ON k.user_id = i.user_id AND k.current IS TRUE
            WHERE i.key IS NOT NULL
            ON CONFLICT (inbox_id, user_key_id) DO NOTHING
            """
        )
        _logger.info("vault: migrated %s vault inbox keys", cr.rowcount)

    # Drop the obsolete legacy columns
    cr.execute("ALTER TABLE res_users_key DROP COLUMN IF EXISTS current")
    cr.execute("ALTER TABLE vault_right DROP COLUMN IF EXISTS key")
    cr.execute("ALTER TABLE vault_inbox DROP COLUMN IF EXISTS key")
