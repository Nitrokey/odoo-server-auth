# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import json
import logging
from datetime import datetime, timedelta
from uuid import uuid4

from odoo import _, api, fields, models

_logger = logging.getLogger(__name__)


class VaultInbox(models.Model):
    _name = "vault.inbox"
    _description = "Vault share incoming secrets"

    token = fields.Char(default=lambda self: uuid4(), readonly=True, copy=False)
    inbox_link = fields.Char(
        compute="_compute_inbox_link",
        readonly=True,
        help="Using this link you can write to the current inbox. If you want people "
        "to create new inboxes you should give them your inbox link from your key "
        "management.",
    )
    user_id = fields.Many2one(
        "res.users",
        "Vault",
        required=True,
    )
    name = fields.Char(required=True)
    secret = fields.Char(readonly=True)
    filename = fields.Char()
    secret_file = fields.Binary(attachment=False, readonly=True)
    wrapped_key_ids = fields.One2many("vault.inbox.wrap", "inbox_id", "Wrapped keys")
    key = fields.Char(compute="_compute_key", store=False)
    iv = fields.Char(required=True)
    accesses = fields.Integer(
        "Access counter",
        default=1,
        help="If this is 0 the inbox can't be written using the link",
    )
    expiration = fields.Datetime(
        default=lambda self: datetime.now() + timedelta(days=7),
        help="If expired the inbox can't be written using the link",
    )
    log_ids = fields.One2many("vault.inbox.log", "inbox_id", "Log", readonly=True)

    _sql_constraints = [
        (
            "value_check",
            "CHECK(secret IS NOT NULL OR secret_file IS NOT NULL)",
            "No value found",
        ),
    ]

    @api.depends("wrapped_key_ids.key")
    def _compute_key(self):
        for rec in self:
            rec.key = json.dumps(
                {w.user_key_id.uuid: w.key for w in rec.wrapped_key_ids if w.key}
            )

    @api.depends("token")
    def _compute_inbox_link(self):
        base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        for rec in self:
            rec.inbox_link = f"{base_url}/vault/inbox/{rec.token}"

    def read(self, *args, **kwargs):
        # Always load the binary instead of the size
        return super(VaultInbox, self.with_context(bin_size=False)).read(
            *args, **kwargs
        )

    @api.model
    def find_inbox(self, token):
        return self.search([("token", "=", token)])

    def _build_wrapped_keys(self, keys, user):
        """Build the (0, 0, {...}) commands for the per-key wrappings from a
        {user_key_uuid: wrapped_key} mapping."""
        by_uuid = {key.uuid: key for key in user.sudo().keys}
        commands = []
        for uuid, wrapped in (keys or {}).items():
            user_key = by_uuid.get(uuid)
            if user_key and wrapped:
                commands.append((0, 0, {"user_key_id": user_key.id, "key": wrapped}))
        return commands

    def store_in_inbox(
        self,
        name,
        secret,
        secret_file,
        iv,
        keys,
        user,
        filename,
        ip=None,
    ):
        log_info = {"name": user.name, "ip": ip or "n/a"}
        wrapped = self._build_wrapped_keys(keys, user)
        if len(self) == 0:
            log = _("Created by %(name)s via %(ip)s") % log_info
            return self.create(
                {
                    "name": name,
                    "accesses": 0,
                    "iv": iv,
                    "wrapped_key_ids": wrapped,
                    "secret": secret or None,
                    "secret_file": secret_file or None,
                    "filename": filename,
                    "user_id": user.id,
                    "log_ids": [(0, 0, {"name": log})],
                }
            )

        self.ensure_one()
        if self.accesses > 0 and datetime.now() < self.expiration:
            log = _("Written by %(name)s via %(ip)s") % log_info

            self.write(
                {
                    "accesses": self.accesses - 1,
                    "iv": iv,
                    "wrapped_key_ids": [(5, 0, 0)] + wrapped,
                    "secret": secret or None,
                    "secret_file": secret_file or None,
                    "filename": filename,
                    "log_ids": [(0, 0, {"name": log})],
                }
            )
            return self
