# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import fields, models


class VaultInboxWrap(models.Model):
    """Stores the symmetric key of an inbox wrapped with the public key of a
    single key of the user. Every key of the inbox owner gets its own wrapping
    so that any of the owner's keys can unwrap the inbox secret."""

    _name = "vault.inbox.wrap"
    _description = "Vault inbox key wrapping"

    inbox_id = fields.Many2one(
        "vault.inbox",
        "Inbox",
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
    # Inbox symmetric key wrapped with the public key of user_key_id
    key = fields.Char()

    _sql_constraints = [
        (
            "inbox_key_uniq",
            "UNIQUE(inbox_id, user_key_id)",
            "The key must be unique per inbox",
        ),
    ]
