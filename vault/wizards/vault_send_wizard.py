# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import json
import logging

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class VaultSendWizard(models.TransientModel):
    _name = "vault.send.wizard"
    _description = "Wizard to send another user a secret"

    user_id = fields.Many2one(
        "res.users",
        "User",
        required=True,
        domain=[("keys", "!=", False), ("inbox_enabled", "=", True)],
    )
    name = fields.Char(required=True)
    public_keys = fields.Char(compute="_compute_public_keys")
    iv = fields.Char(required=True)
    key_user = fields.Char(required=True)
    key = fields.Char(required=True)
    secret = fields.Char()
    secret_file = fields.Char()
    filename = fields.Char()

    _sql_constraints = [
        (
            "value_check",
            "CHECK(secret IS NOT NULL OR secret_file IS NOT NULL)",
            "No value found",
        ),
    ]

    @api.depends("user_id", "user_id.keys")
    def _compute_public_keys(self):
        for rec in self:
            if rec.user_id:
                rec.public_keys = json.dumps(rec.user_id._get_public_keys())
            else:
                rec.public_keys = "[]"

    def action_send(self):
        if not self.secret and not self.secret_file:
            raise ValidationError(_("Neither a secret nor file was given"))

        self.ensure_one()

        try:
            keys = json.loads(self.key_user or "{}")
        except (ValueError, TypeError):
            keys = {}

        inbox = self.env["vault.inbox"].sudo()
        inbox.create(
            {
                "name": self.name,
                "accesses": 0,
                "secret": self.secret,
                "secret_file": self.secret_file,
                "iv": self.iv,
                "wrapped_key_ids": inbox._build_wrapped_keys(keys, self.user_id),
                "user_id": self.user_id.id,
                "filename": self.filename,
                "log_ids": [(0, 0, {"name": _("Created by %s") % self.user_id.name})],
            }
        )
