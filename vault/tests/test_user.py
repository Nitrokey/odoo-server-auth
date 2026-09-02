# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

from odoo.exceptions import ValidationError

from odoo.addons.base.tests.common import BaseCommon

_logger = logging.getLogger(__name__)


class TestShare(BaseCommon):
    def test_user_inbox(self):
        user = self.env["res.users"].create(
            {"login": "test", "email": "test@test", "name": "test"}
        )

        user.action_new_inbox_token()

        model = self.env["res.users"]
        token = user.inbox_token

        self.assertEqual(user, model.find_user_of_inbox(token))
        self.assertIn(token, user.inbox_link)

        user.inbox_enabled = False
        self.assertEqual(model, model.find_user_of_inbox(token))

        user.action_new_inbox_token()
        self.assertNotEqual(user.inbox_token, token)

    def test_user_key_management(self):
        action = self.env.ref("vault.action_res_users_keys")

        self.assertEqual(action.id, self.env["res.users"].action_get_vault()["id"])

    def test_remove_key(self):
        # A single key can't be removed
        first = self.env["res.users.key"].store(
            40000, "iv", "private", "public", "salt", 42
        )
        self.assertTrue(self.env.user.keys)
        with self.assertRaises(ValidationError):
            self.env.user.remove_vault_key(first)

        # Add a second key and remove the first one
        second = self.env["res.users.key"].store(
            40000, "iv", "more private", "public2", "salt", 42
        )
        self.assertEqual(len(self.env.user.keys), 2)

        self.env.user.remove_vault_key(first)
        self.assertEqual(len(self.env.user.keys), 1)
        self.assertEqual(self.env.user.keys.uuid, second)

        # Removing an unknown key raises
        with self.assertRaises(ValidationError):
            self.env.user.remove_vault_key("unknown")

    def test_store_security_key(self):
        uuid = self.env["res.users.key"].store(
            40000,
            "iv",
            "private",
            "public",
            "salt",
            2,
            key_type="security_key",
            credential_id="credential",
            prf_salt="prf_salt",
            label="My Nitrokey",
        )
        self.assertTrue(uuid)

        key = self.env.user.keys.filtered(lambda k: k.uuid == uuid)
        self.assertEqual(key.key_type, "security_key")
        self.assertEqual(key.credential_id, "credential")
        self.assertEqual(key.prf_salt, "prf_salt")
        self.assertEqual(key.label, "My Nitrokey")

        result = self.env.user.get_vault_keys()
        stored = result["keys"][0]
        self.assertEqual(stored["key_type"], "security_key")
        self.assertEqual(stored["credential_id"], "credential")
        self.assertEqual(stored["prf_salt"], "prf_salt")
        self.assertEqual(stored["label"], "My Nitrokey")

    def test_store_security_key_invalid(self):
        # Missing credential_id and prf_salt
        with self.assertRaises(ValidationError):
            self.env["res.users.key"].store(
                40000, "iv", "private", "public", "salt", 2, key_type="security_key"
            )

        # Invalid key_type
        with self.assertRaises(ValidationError):
            self.env["res.users.key"].store(
                40000, "iv", "private", "public", "salt", 2, key_type="invalid"
            )

    def test_allowed_key_types_default(self):
        # Without any configuration both key types are allowed
        self.assertEqual(self.env.user.vault_allowed_key_types, "all")

    def test_allowed_key_types_security_key(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "vault.allowed_key_types", "security_key"
        )
        self.assertEqual(self.env.user.vault_allowed_key_types, "security_key")

        # Password protected keys are forbidden
        with self.assertRaises(ValidationError):
            self.env["res.users.key"].store(40000, "iv", "private", "public", "salt", 1)

        # Security keys are still allowed
        uuid = self.env["res.users.key"].store(
            40000,
            "iv",
            "private",
            "public",
            "salt",
            1,
            key_type="security_key",
            credential_id="credential",
            prf_salt="prf_salt",
        )
        self.assertTrue(uuid)

    def test_allowed_key_types_password(self):
        self.env["ir.config_parameter"].sudo().set_param(
            "vault.allowed_key_types", "password"
        )
        self.assertEqual(self.env.user.vault_allowed_key_types, "password")

        # Security key protected keys are forbidden
        with self.assertRaises(ValidationError):
            self.env["res.users.key"].store(
                40000,
                "iv",
                "private",
                "public",
                "salt",
                1,
                key_type="security_key",
                credential_id="credential",
                prf_salt="prf_salt",
            )

        # Password protected keys are still allowed
        uuid = self.env["res.users.key"].store(
            40000, "iv", "private", "public", "salt", 1
        )
        self.assertTrue(uuid)
