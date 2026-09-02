# © 2021-2024 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import json
import logging
from uuid import uuid4

from odoo import _, api, fields, models

_logger = logging.getLogger(__name__)


class Vault(models.Model):
    _name = "vault"
    _description = "Vault"
    _inherit = ["vault.abstract"]
    _order = "name"

    user_id = fields.Many2one(
        "res.users",
        "Owner",
        readonly=True,
        default=lambda self: self.env.user,
        required=True,
    )
    right_ids = fields.One2many(
        "vault.right",
        "vault_id",
        "Rights",
        default=lambda self: self._get_default_rights(),
    )
    entry_ids = fields.One2many("vault.entry", "vault_id", "Entries")
    field_ids = fields.One2many("vault.field", "vault_id", "Fields")
    file_ids = fields.One2many("vault.file", "vault_id", "Files")
    log_ids = fields.One2many("vault.log", "vault_id", "Log", readonly=True)
    reencrypt_required = fields.Boolean(default=False)

    # Access control
    perm_user = fields.Many2one("res.users", compute="_compute_access", store=False)
    allowed_read = fields.Boolean(compute="_compute_access", store=False)
    allowed_create = fields.Boolean(compute="_compute_access", store=False)
    allowed_share = fields.Boolean(compute="_compute_access", store=False)
    allowed_write = fields.Boolean(compute="_compute_access", store=False)
    allowed_delete = fields.Boolean(compute="_compute_access", store=False)

    master_key = fields.Char(
        compute="_compute_master_key",
        inverse="_inverse_master_key",
        store=False,
    )

    uuid = fields.Char(default=lambda self: uuid4(), required=True, readonly=True)
    name = fields.Char(required=True)
    note = fields.Text()

    _sql_constraints = [
        ("uuid_uniq", "UNIQUE(uuid)", "The UUID must be unique."),
    ]

    @api.depends("right_ids.user_id")
    def _compute_access(self):
        user = self.env.user
        for rec in self.sudo():
            rec.perm_user = user.id

            if user == rec.user_id:
                rec.write(
                    {
                        "allowed_create": True,
                        "allowed_share": True,
                        "allowed_write": True,
                        "allowed_delete": True,
                        "allowed_read": True,
                    }
                )
                continue

            rights = rec.right_ids
            rec.allowed_read = user in rights.mapped("user_id")
            rec.allowed_create = user in rights.filtered("perm_create").mapped(
                "user_id"
            )
            rec.allowed_share = user in rights.filtered("perm_share").mapped("user_id")
            rec.allowed_write = user in rights.filtered("perm_write").mapped("user_id")
            rec.allowed_delete = user in rights.filtered("perm_delete").mapped(
                "user_id"
            )

    @api.depends("right_ids.wrapped_key_ids.key")
    def _compute_master_key(self):
        domain = [("user_id", "=", self.env.uid)]
        for rec in self:
            rights = rec.right_ids.filtered_domain(domain)
            wrapped = rights.wrapped_key_ids if rights else self.env["vault.right.key"]
            rec.master_key = json.dumps(
                {w.user_key_id.uuid: w.key for w in wrapped if w.key}
            )

    def _inverse_master_key(self):
        domain = [("user_id", "=", self.env.uid)]
        for rec in self:
            rights = rec.right_ids.filtered_domain(domain)
            if not rights:
                continue

            try:
                keys = json.loads(rec.master_key or "{}")
            except (ValueError, TypeError):
                continue

            rec._store_wrapped_keys(rights, keys)

    def _store_wrapped_keys(self, right, keys):
        """Create/update/remove the vault.right.key rows of a right to match the
        given {user_key_uuid: wrapped_key} mapping."""
        right.ensure_one()
        user_keys = right.user_id.sudo().keys
        by_uuid = {key.uuid: key for key in user_keys}
        existing = {w.user_key_id.uuid: w for w in right.wrapped_key_ids}

        for uuid, wrapped in keys.items():
            user_key = by_uuid.get(uuid)
            if not user_key or not wrapped:
                continue

            if uuid in existing:
                existing[uuid].key = wrapped
            else:
                self.env["vault.right.key"].sudo().create(
                    {
                        "right_id": right.id,
                        "user_key_id": user_key.id,
                        "key": wrapped,
                    }
                )

    def _get_default_rights(self):
        return [
            (
                0,
                0,
                {
                    "user_id": self.env.uid,
                    "perm_create": True,
                    "perm_write": True,
                    "perm_delete": True,
                    "perm_share": True,
                },
            )
        ]

    def _log_entry(self, msg, state):
        self.ensure_one()
        return (
            self.env["vault.log"]
            .sudo()
            .create(
                {
                    "vault_id": self.id,
                    "user_id": self.env.uid,
                    "message": msg,
                    "state": state,
                }
            )
        )

    def share_public_keys(self):
        self.ensure_one()
        result = []
        for right in self.right_ids:
            result.append(
                {
                    "user": right.user_id.id,
                    "public_keys": right.user_id._get_public_keys(),
                }
            )
        return result

    def action_open_import_wizard(self):
        self.ensure_one()
        wizard = self.env.ref("vault.view_vault_import_wizard")
        return {
            "name": _("Import from file"),
            "type": "ir.actions.act_window",
            "view_mode": "form",
            "res_model": "vault.import.wizard",
            "views": [(wizard.id, "form")],
            "view_id": wizard.id,
            "target": "new",
            "context": {"default_vault_id": self.id},
        }

    def action_open_export_wizard(self):
        self.ensure_one()
        wizard = self.env.ref("vault.view_vault_export_wizard")
        return {
            "name": _("Export to file"),
            "type": "ir.actions.act_window",
            "view_mode": "form",
            "res_model": "vault.export.wizard",
            "views": [(wizard.id, "form")],
            "view_id": wizard.id,
            "target": "new",
            "context": {"default_vault_id": self.id},
        }
