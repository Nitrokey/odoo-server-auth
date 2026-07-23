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

    def test_invalidation(self):
        self.env["res.users.key"].store(
            40000, "invalid", "invalid", "invalid", "invalid", 42
        )
        self.assertTrue(self.env.user.keys.filtered("current"))

        vault = self.env["vault"].create({"name": "Test"})
        self.assertTrue(vault.right_ids)

        inbox = self.env["vault.inbox"].create(
            {
                "name": "Inbox Test",
                "secret": "secret",
                "iv": "iv",
                "user_id": self.env.uid,
                "key": "key",
                "secret_file": "",
                "filename": "",
            }
        )

        self.env.user.action_invalidate_key()
        self.assertFalse(self.env.user.keys.filtered("current"))
        self.assertFalse(inbox.exists())
        self.assertFalse(vault.right_ids.exists())

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
        )
        self.assertTrue(uuid)

        key = self.env.user.active_key
        self.assertEqual(key.key_type, "security_key")
        self.assertEqual(key.credential_id, "credential")
        self.assertEqual(key.prf_salt, "prf_salt")

        keys = self.env.user.get_vault_keys()
        self.assertEqual(keys["key_type"], "security_key")
        self.assertEqual(keys["credential_id"], "credential")
        self.assertEqual(keys["prf_salt"], "prf_salt")

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
