# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

_logger = logging.getLogger(__name__)


def migrate(cr, version):
    """Create the name_id column before the ORM loads the model so the new
    required field does not break the update on databases with existing data.
    The column is backfilled in the post-migration script.
    """
    cr.execute(
        """
        ALTER TABLE vault_field
        ADD COLUMN IF NOT EXISTS name_id integer
        """
    )
