# © 2021 Florian Kantelberg - initOS GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).

import json
import logging

from odoo import _, http
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)


class Controller(http.Controller):
    @http.route("/vault/inbox/<string:token>", type="http", auth="public", website=True)
    def vault_inbox(self, token):
        ctx = {"disable_footer": True, "token": token}
        # Find the right token
        inbox = request.env["vault.inbox"].sudo().find_inbox(token)
        user = request.env["res.users"].sudo().find_user_of_inbox(token)
        if len(inbox) == 1 and inbox.accesses > 0:
            ctx.update(
                {"name": inbox.name, "publics": inbox.user_id._get_public_keys()}
            )
        elif len(inbox) == 0 and len(user) == 1:
            ctx["publics"] = user._get_public_keys()

        # A valid token would mean we found at least one public key
        if not ctx.get("publics"):
            ctx["error"] = _("Invalid token")
            return request.render("vault.inbox", ctx)

        ctx["publics_json"] = json.dumps(ctx["publics"])

        # Just render if GET method
        if request.httprequest.method != "POST":
            return request.render("vault.inbox", ctx)

        # Check the param
        name = request.params.get("name")
        secret = request.params.get("encrypted")
        secret_file = request.params.get("encrypted_file")
        filename = request.params.get("filename")
        iv = request.params.get("iv")
        # The keys are submitted as a JSON encoded {user_key_uuid: wrapped} map
        try:
            keys = json.loads(request.params.get("keys") or "{}")
        except (ValueError, TypeError):
            keys = {}
        if not name:
            ctx["error"] = _("Please specify a name")
            return request.render("vault.inbox", ctx)

        if not secret and not secret_file:
            ctx["error"] = _("No secret found")
            return request.render("vault.inbox", ctx)

        if secret_file and not filename:
            ctx["error"] = _("Missing filename")
            return request.render("vault.inbox", ctx)

        if not iv or not keys:
            ctx["error"] = _("Something went wrong with the encryption")
            return request.render("vault.inbox", ctx)

        try:
            inbox.store_in_inbox(
                name,
                secret,
                secret_file,
                iv,
                keys,
                user,
                filename,
                ip=request.httprequest.remote_addr,
            )
        except Exception as e:
            _logger.exception(e)
            ctx["error"] = _(
                "An error occured. Please contact the user or administrator"
            )
            return request.render("vault.inbox", ctx)

        ctx["message"] = _("Successfully stored")
        return request.render("vault.inbox", ctx)

    @http.route("/vault/public", type="json")
    def vault_public(self, user_id):
        """Get the public keys of a specific user"""
        user = request.env["res.users"].sudo().browse(user_id).exists()
        if not user or not user.keys:
            return {}

        return {"public_keys": user._get_public_keys()}

    @http.route("/vault/inbox/get", auth="user", type="json")
    def vault_get_inbox(self):
        """Get the inbox keys wrapped per key of the user"""
        result = {}
        for inbox in request.env.user.inbox_ids:
            result[inbox.token] = {
                w.user_key_id.uuid: w.key for w in inbox.wrapped_key_ids if w.key
            }
        return result

    @http.route("/vault/inbox/store", auth="user", type="json")
    def vault_store_inbox(self, keys):
        """Store the inbox keys wrapped per key of the user.

        ``keys`` is a {token: {user_key_uuid: wrapped_key}} mapping.
        """
        if not isinstance(keys, dict):
            return

        user = request.env.user
        for inbox in user.inbox_ids:
            wrapping = keys.get(inbox.token)
            if not isinstance(wrapping, dict):
                continue

            inbox.sudo().write(
                {
                    "wrapped_key_ids": [(5, 0, 0)]
                    + inbox._build_wrapped_keys(wrapping, user)
                }
            )

    @http.route("/vault/keys/store", auth="user", type="json")
    def vault_store_keys(self, **kwargs):
        """Store the key pair for the current user"""
        return request.env["res.users.key"].store(**kwargs)

    @http.route("/vault/keys/get", auth="user", type="json")
    def vault_get_keys(self):
        """Get all keys of the current user"""
        return request.env.user.get_vault_keys()

    @http.route("/vault/keys/remove", auth="user", type="json")
    def vault_remove_key(self, uuid):
        """Remove a single key of the current user"""
        return request.env.user.remove_vault_key(uuid)

    @http.route("/vault/rights/get", auth="user", type="json")
    def vault_get_right_keys(self):
        """Get the master keys wrapped per key of the user"""
        result = {}
        for right in request.env.user.vault_right_ids:
            result[right.vault_id.uuid] = {
                w.user_key_id.uuid: w.key for w in right.wrapped_key_ids if w.key
            }
        return result

    @http.route("/vault/rights/store", auth="user", type="json")
    def vault_store_right_keys(self, keys):
        """Store the master keys wrapped per key of the user.

        ``keys`` is a {vault_uuid: {user_key_uuid: wrapped_key}} mapping.
        """
        if not isinstance(keys, dict):
            return

        vault_model = request.env["vault"]
        for right in request.env.user.vault_right_ids:
            wrapping = keys.get(right.vault_id.uuid)
            if not isinstance(wrapping, dict):
                continue

            vault_model._store_wrapped_keys(right.sudo(), wrapping)

    @http.route("/vault/replace", auth="user", type="json")
    def vault_replace(self, data):
        """Replace the master keys and values within a single transaction"""
        if not isinstance(data, list):
            return

        vault = request.env["vault"].with_context(vault_skip_log=True)
        for changes in data:
            record = vault.env[changes["model"]].browse(changes["id"])
            if not record.vault_id.allowed_write:
                raise AccessDenied()

            vault |= record.vault_id
            if record._name in ("vault.field", "vault.file"):
                record.write({k: v for k, v in changes.items() if k in ["iv", "value"]})
            elif record._name == "vault.right":
                wrapping = changes.get("keys")
                if isinstance(wrapping, dict):
                    request.env["vault"]._store_wrapped_keys(record.sudo(), wrapping)

        for v in vault:
            v._log_entry("Replaced the keys", "info")

        vault.sudo().write({"reencrypt_required": False})
