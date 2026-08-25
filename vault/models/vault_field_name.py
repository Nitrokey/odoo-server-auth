# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import api, fields, models


class VaultFieldName(models.Model):
    _name = "vault.field.name"
    _description = "Vault field name"
    _order = "name"

    name = fields.Char(required=True)

    _sql_constraints = [
        (
            "name_uniq",
            "unique(name)",
            "The name must be unique!",
        ),
    ]

    @api.model
    def _get_or_create(self, name):
        """Return the matching name record (case-insensitive) or create it."""
        if not name:
            return self.browse()

        record = self.search([("name", "=ilike", name)], limit=1)
        if record:
            return record
        return self.create({"name": name})
