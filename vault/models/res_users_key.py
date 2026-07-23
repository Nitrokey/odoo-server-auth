# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging
import re
from hashlib import sha256
from uuid import uuid4

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class ResUsersKey(models.Model):
    _name = "res.users.key"
    _description = "User data of a vault"
    _rec_name = "fingerprint"
    _order = "create_date DESC"

    user_id = fields.Many2one("res.users", required=True)
    uuid = fields.Char(default=lambda self: uuid4(), required=True, readonly=True)
    current = fields.Boolean(default=True, readonly=True)
    fingerprint = fields.Char(compute="_compute_fingerprint", store=True)
    public = fields.Char(required=True, readonly=True)
    salt = fields.Char(required=True, readonly=True)
    iv = fields.Char(required=True, readonly=True)
    iterations = fields.Integer(required=True, readonly=True)
    version = fields.Integer(readonly=True)
    key_type = fields.Selection(
        [("password", "Password"), ("security_key", "Security Key")],
        default="password",
        required=True,
        readonly=True,
    )
    credential_id = fields.Char(readonly=True)
    prf_salt = fields.Char(readonly=True)
    # Encrypted with master password of user
    private = fields.Char(required=True, readonly=True)

    @api.depends("public")
    def _compute_fingerprint(self):
        for rec in self:
            if rec.public:
                hashed = sha256(rec.public.encode()).hexdigest()
                rec.fingerprint = ":".join(re.findall(r".{2}", hashed))
            else:
                rec.fingerprint = False

    def _prepare_values(
        self,
        iterations,
        iv,
        private,
        public,
        salt,
        version,
        key_type="password",
        credential_id=None,
        prf_salt=None,
    ):
        return {
            "iterations": iterations,
            "iv": iv,
            "private": private,
            "public": public,
            "salt": salt,
            "user_id": self.env.uid,
            "current": True,
            "version": version,
            "key_type": key_type,
            "credential_id": credential_id,
            "prf_salt": prf_salt,
        }

    def store(
        self,
        iterations,
        iv,
        private,
        public,
        salt,
        version,
        key_type="password",
        credential_id=None,
        prf_salt=None,
    ):
        if not all(isinstance(x, str) and x for x in [public, private, iv, salt]):
            raise ValidationError(_("Invalid parameter"))

        if not isinstance(iterations, int) or iterations < 4000:
            raise ValidationError(_("Invalid parameter"))

        if not isinstance(version, int):
            raise ValidationError(_("Invalid parameter"))

        if key_type not in ("password", "security_key"):
            raise ValidationError(_("Invalid parameter"))

        if key_type == "security_key" and not all(
            isinstance(x, str) and x for x in [credential_id, prf_salt]
        ):
            raise ValidationError(_("Invalid parameter"))

        allowed = self.env.user.vault_allowed_key_types
        if allowed == "password" and key_type != "password":
            raise ValidationError(
                _("The administrator only allows password protected keys")
            )
        if allowed == "security_key" and key_type != "security_key":
            raise ValidationError(
                _("The administrator enforces the usage of a security key")
            )

        domain = [
            ("user_id", "=", self.env.uid),
            ("private", "=", private),
        ]
        key = self.search(domain)
        if not key:
            # Disable all current keys
            self.env.user.keys.write({"current": False})

            rec = self.create(
                self._prepare_values(
                    iterations,
                    iv,
                    private,
                    public,
                    salt,
                    version,
                    key_type,
                    credential_id,
                    prf_salt,
                )
            )
            return rec.uuid

        return False

    def extract_public_key(self, user):
        user = self.sudo().search([("user_id", "=", user), ("current", "=", True)])
        return user.public or None
