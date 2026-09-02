# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import json

from odoo import api, fields, models


class VaultRight(models.Model):
    _name = "vault.right"
    _description = "Vault rights"
    _inherit = ["vault.abstract"]
    _order = "user_id"

    vault_id = fields.Many2one(
        "vault",
        "Vault",
        readonly=True,
        required=True,
        ondelete="cascade",
    )
    master_key = fields.Char(related="vault_id.master_key", readonly=True, store=False)
    user_id = fields.Many2one(
        "res.users",
        "User",
        domain=[("keys", "!=", False)],
        required=True,
    )
    public_keys = fields.Char(
        compute="_compute_public_keys", readonly=True, store=False
    )
    perm_create = fields.Boolean(
        "Create",
        default=lambda self: self._get_is_owner(),
        help="Allow to create in the vault",
    )
    perm_write = fields.Boolean(
        "Write",
        default=lambda self: self._get_is_owner(),
        help="Allow to write to the vault",
    )
    perm_share = fields.Boolean(
        "Share",
        default=lambda self: self._get_is_owner(),
        help="Allow to share a vault with new users",
    )
    perm_delete = fields.Boolean(
        "Delete",
        default=lambda self: self._get_is_owner(),
        help="Allow to delete a vault",
    )

    perm_user = fields.Many2one(related="vault_id.perm_user", store=False)
    allowed_read = fields.Boolean(related="vault_id.allowed_read", store=False)
    allowed_create = fields.Boolean(related="vault_id.allowed_create", store=False)
    allowed_write = fields.Boolean(related="vault_id.allowed_write", store=False)
    allowed_share = fields.Boolean(related="vault_id.allowed_share", store=False)
    allowed_delete = fields.Boolean(related="vault_id.allowed_delete", store=False)

    # The master key wrapped once per key of the user
    wrapped_key_ids = fields.One2many("vault.right.key", "right_id", "Wrapped keys")
    # JSON {user_key_uuid: wrapped_key} used to set the wrappings from the client
    wrapped_keys = fields.Char(
        compute="_compute_wrapped_keys",
        inverse="_inverse_wrapped_keys",
        store=False,
    )

    _sql_constraints = (
        ("user_uniq", "UNIQUE(user_id, vault_id)", "The user must be unique"),
    )

    def _get_is_owner(self):
        return self.env.user == self.vault_id.user_id

    @api.depends("user_id", "user_id.keys")
    def _compute_public_keys(self):
        for rec in self:
            rec.public_keys = json.dumps(rec.user_id._get_public_keys())

    @api.depends("wrapped_key_ids.key")
    def _compute_wrapped_keys(self):
        for rec in self:
            rec.wrapped_keys = json.dumps(
                {w.user_key_id.uuid: w.key for w in rec.wrapped_key_ids if w.key}
            )

    def _inverse_wrapped_keys(self):
        for rec in self:
            try:
                keys = json.loads(rec.wrapped_keys or "{}")
            except (ValueError, TypeError):
                continue

            self.env["vault"]._store_wrapped_keys(rec, keys)

    def log_access(self):
        for rec in self:
            rights = ", ".join(
                sorted(
                    ["read"]
                    + [
                        right
                        for right in ["create", "write", "share", "delete"]
                        if getattr(rec, f"perm_{right}", False)
                    ]
                )
            )

            rec.vault_id.log_info(
                f"Grant access to user {rec.user_id.display_name}: {rights}"
            )

    @api.model_create_multi
    def create(self, vals_list):
        res = super().create(vals_list)
        if not res.env.su and res.filtered(lambda r: not r.allowed_share):
            self.raise_access_error()

        res.log_access()
        return res

    def write(self, values):
        res = super().write(values)
        perms = ["perm_write", "perm_delete", "perm_share", "perm_create"]
        if any(x in values for x in perms):
            self.log_access()

        return res

    def unlink(self):
        for rec in self:
            rec.vault_id.log_info(f"Removed user {self.user_id.display_name}")
            rec.vault_id.reencrypt_required = True

        return super().unlink()
