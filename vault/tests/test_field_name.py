# © 2026 Nitrokey GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import logging

from psycopg2 import IntegrityError

from odoo.tools import mute_logger

from odoo.addons.base.tests.common import BaseCommon

_logger = logging.getLogger(__name__)


class TestFieldName(BaseCommon):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.vault = cls.env["vault"].create({"name": "Vault"})
        cls.entry = cls.env["vault.entry"].create(
            {"vault_id": cls.vault.id, "name": "Entry"}
        )

    def _create_field(self, name_id):
        return self.env["vault.field"].create(
            {
                "entry_id": self.entry.id,
                "name_id": name_id.id,
                "value": "Value",
            }
        )

    def test_get_or_create_dedup_case_insensitive(self):
        Name = self.env["vault.field.name"]
        first = Name._get_or_create("Password")
        again = Name._get_or_create("password")
        self.assertEqual(first, again)

        other = Name._get_or_create("Username")
        self.assertNotEqual(first, other)

    @mute_logger("odoo.sql_db")
    def test_unique_constraint(self):
        self.env["vault.field.name"].create({"name": "Token"})
        with self.assertRaises(IntegrityError):
            self.env["vault.field.name"].create({"name": "Token"})

    def test_field_name_mirrored_on_field(self):
        name = self.env["vault.field.name"].create({"name": "Secret"})
        field = self._create_field(name)
        self.assertEqual(field.name, "Secret")

        # Renaming the catalog entry updates the stored mirror on the field
        name.name = "Renamed"
        self.assertEqual(field.name, "Renamed")
