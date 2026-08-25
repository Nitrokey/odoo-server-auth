# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Migrate the free-text secret names of vault.field into the new managed
    catalog vault.field.name and link every field to its catalog entry.

    De-duplication is case-insensitive: names differing only in case share a
    single catalog entry (the first encountered spelling is kept as label).
    """
    # Nothing to migrate if the legacy column is gone
    cr.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'vault_field' AND column_name = 'name'
        """
    )
    if not cr.fetchone():
        return

    # Collect a representative original-case label per case-insensitive key
    cr.execute(
        """
        SELECT DISTINCT ON (lower(name)) name
        FROM vault_field
        WHERE name IS NOT NULL AND name != ''
        ORDER BY lower(name), name
        """
    )
    labels = [row[0] for row in cr.fetchall()]

    # Map lower(name) -> vault_field_name.id, reusing existing catalog entries
    name_map = {}
    for label in labels:
        key = label.lower()
        cr.execute(
            "SELECT id FROM vault_field_name WHERE lower(name) = %s LIMIT 1",
            (key,),
        )
        row = cr.fetchone()
        if row:
            name_map[key] = row[0]
            continue

        cr.execute(
            "INSERT INTO vault_field_name (name) VALUES (%s) RETURNING id",
            (label,),
        )
        name_map[key] = cr.fetchone()[0]

    # Backfill name_id on every field by matching the case-insensitive key
    for key, name_id in name_map.items():
        cr.execute(
            "UPDATE vault_field SET name_id = %s WHERE lower(name) = %s",
            (name_id, key),
        )

    _logger.info("Migrated vault.field names into %s catalog entries", len(name_map))
