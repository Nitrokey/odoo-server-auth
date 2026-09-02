# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import fields, models


class VaultRightKey(models.Model):
    """Stores the master key of a vault wrapped with the public key of a single
    key of the user. Every key of a user with a right gets its own wrapping so
    that any of the user's keys can unwrap the master key."""

    _name = "vault.right.key"
    _description = "Vault right key wrapping"

    right_id = fields.Many2one(
        "vault.right",
        "Right",
        readonly=True,
        required=True,
        ondelete="cascade",
    )
    user_key_id = fields.Many2one(
        "res.users.key",
        "User Key",
        readonly=True,
        required=True,
        ondelete="cascade",
    )
    # Master key wrapped with the public key of user_key_id
    key = fields.Char()

    _sql_constraints = [
        (
            "right_key_uniq",
            "UNIQUE(right_id, user_key_id)",
            "The key must be unique per right",
        ),
    ]
