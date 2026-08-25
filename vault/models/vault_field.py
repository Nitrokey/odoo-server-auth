# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

from odoo import fields, models

_logger = logging.getLogger(__name__)


class VaultField(models.Model):
    _name = "vault.field"
    _description = "Field of a vault"
    _order = "name"
    _inherit = ["vault.abstract.field", "vault.abstract"]

    name_id = fields.Many2one(
        "vault.field.name",
        "Name",
        required=True,
        ondelete="restrict",
    )
    # Override the free-text name inherited from vault.abstract.field with a
    # stored mirror of the selected catalog entry. This keeps _order, logging
    # and the JSON export working while the name is managed via name_id.
    name = fields.Char(
        related="name_id.name",
        store=True,
        readonly=True,
    )
    value = fields.Char(required=True)
