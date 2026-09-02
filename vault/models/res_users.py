# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging
from uuid import uuid4

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    keys = fields.One2many("res.users.key", "user_id")
    vault_right_ids = fields.One2many("vault.right", "user_id", readonly=True)
    inbox_ids = fields.One2many("vault.inbox", "user_id")
    inbox_enabled = fields.Boolean(default=True)
    inbox_link = fields.Char(compute="_compute_inbox_link", readonly=True, store=False)
    inbox_token = fields.Char(default=lambda self: uuid4(), readonly=True)
    vault_allowed_key_types = fields.Char(
        compute="_compute_vault_allowed_key_types",
        store=False,
    )

    def _compute_vault_allowed_key_types(self):
        allowed = (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param("vault.allowed_key_types", "all")
        )
        if allowed not in ("password", "security_key", "all"):
            allowed = "all"
        for rec in self:
            rec.vault_allowed_key_types = allowed

    def _get_public_keys(self):
        self.ensure_one()
        return [{"uuid": key.uuid, "public": key.public} for key in self.sudo().keys]

    @api.depends("inbox_token")
    def _compute_inbox_link(self):
        base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")
        for rec in self:
            rec.inbox_link = f"{base_url}/vault/inbox/{rec.inbox_token}"

    @api.model
    def action_get_vault(self):
        result = self.env["ir.actions.act_window"]._for_xml_id(
            "vault.action_res_users_keys"
        )
        result["res_id"] = self.env.uid
        return result

    def action_new_inbox_token(self):
        self.ensure_one()
        self.sudo().inbox_token = uuid4()
        return self.action_get_vault()

    def remove_vault_key(self, uuid):
        """Remove a single key of the user. The caller (browser) is responsible
        for rotating the master keys of the affected vaults before removing the
        key. Removing the last key is not allowed."""
        self.ensure_one()
        keys = self.sudo().keys
        if len(keys) <= 1:
            raise ValidationError(_("You can't remove your last key"))

        key = keys.filtered(lambda k: k.uuid == uuid)
        if not key:
            raise ValidationError(_("Unknown key"))

        key.unlink()
        self.env["vault"].search([])._compute_access()
        return True

    @api.model
    def find_user_of_inbox(self, token):
        return self.search([("inbox_token", "=", token), ("inbox_enabled", "=", True)])

    def _key_values(self, key):
        return {
            "iterations": key.iterations,
            "iv": key.iv,
            "private": key.private,
            "public": key.public,
            "salt": key.salt,
            "uuid": key.uuid,
            "version": key.version,
            "key_type": key.key_type,
            "credential_id": key.credential_id,
            "prf_salt": key.prf_salt,
            "label": key.label,
        }

    def get_vault_keys(self):
        self.ensure_one()

        return {
            "keys": [self._key_values(key) for key in self.sudo().keys],
            "allowed_key_types": self.vault_allowed_key_types,
        }
