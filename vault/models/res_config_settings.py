# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    module_vault_share = fields.Boolean()
    group_vault_export = fields.Boolean(
        "Export Vaults", implied_group="vault.group_vault_export"
    )
    group_vault_import = fields.Boolean(
        "Import Vaults", implied_group="vault.group_vault_import"
    )
    vault_allowed_key_types = fields.Selection(
        [
            ("password", "Password only"),
            ("security_key", "Security key only"),
            ("all", "Password and security key"),
        ],
        string="Allowed Key Types",
        default="all",
        config_parameter="vault.allowed_key_types",
        help="Restrict which protection methods can be used for newly "
        "generated private keys of the vault. Existing keys are not affected.",
    )
