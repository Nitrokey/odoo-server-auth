# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
from contextlib import contextmanager

from odoo import SUPERUSER_ID, api, models
from odoo.exceptions import AccessDenied
from odoo.http import request

# from threading import current_thread


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    # HACK https://github.com/odoo/odoo/issues/24183
    # TODO Remove in v12, and use normal odoo.http.request to get details
    # @api.model_cr
    # def _register_hook(self):
    #     """🐒-patch XML-RPC controller to know remote address."""
    #     original_fn = wsgi_server.application_unproxied
    #
    #     def _patch(environ, start_response):
    #         current_thread().environ = environ
    #         return original_fn(environ, start_response)
    #
    #     wsgi_server.application_unproxied = _patch

    # Helpers to track authentication attempts
    @classmethod
    @contextmanager
    def _auth_attempt(cls, login):
        """Start an authentication attempt and track its state."""
        try:
            cls.environ = request.httprequest.environ
        except RuntimeError:
            _logger.info(
                "Request: Unbound"
            )
        try:
            # Check if this call is nested
            attempt_id = cls.environ["auth_attempt_id"]
        except KeyError:
            # Not nested; create a new attempt
            attempt_id = cls._auth_attempt_new(login)
        if not attempt_id:
            # No attempt was created, so there's nothing to do here
            yield
        try:
            cls.environ["auth_attempt_id"] = attempt_id
            result = "successful"
            try:
                yield
            except AccessDenied as error:
                result = getattr(error, "reason", "failed")
                raise
            finally:
                cls._auth_attempt_update({"result": result})
        finally:
            try:
                del cls.environ["auth_attempt_id"]
            except KeyError:
                _logger.info(
                    "KeyError: auth_attempt_id was deleted already"
                )  # It was deleted already

    @classmethod
    def _auth_attempt_force_raise(cls, login, method):
        """Force a method to raise an AccessDenied on falsey return."""
        with cls._auth_attempt(login):
            result = method()
            # TODO: Not in use right now,
            # TODO: So, it is more likely to remove these 2 lines of code.
            # if not result:
            #     raise AccessDenied()
        return result

    @classmethod
    def _auth_attempt_new(cls, login):
        """Store one authentication attempt, not knowing the result."""
        # Get the right remote address
        remote_addr = cls.environ.get("REMOTE_ADDR", False)
        # Exit if it doesn't make sense to store this attempt
        if not remote_addr:
            return False
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            attempt = env["res.authentication.attempt"].create(
                {
                    "login": login,
                    "remote": remote_addr,
                }
            )
            return attempt.id

    @classmethod
    def _auth_attempt_update(cls, values):
        """Update a given auth attempt if we still ignore its result."""
        auth_id = cls.environ.get("auth_attempt_id", False)
        if not auth_id:
            return {}  # No running auth attempt; nothing to do
        # Use a separate cursor to keep changes always
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            attempt = env["res.authentication.attempt"].browse(auth_id)
            # Update only on 1st call
            if not attempt.result:
                attempt.write(values)
            return attempt.copy_data()[0] if attempt else {}

    # Override all auth-related core methods
    @classmethod
    def _login(cls, db, login, password, user_agent_env):
        return cls._auth_attempt_force_raise(
            login,
            lambda: super(ResUsers, cls)._login(db, login, password, user_agent_env),
        )

    @classmethod
    def authenticate(cls, db, login, password, user_agent_env):
        return cls._auth_attempt_force_raise(
            login,
            lambda: super(ResUsers, cls).authenticate(
                db, login, password, user_agent_env
            ),
        )

    @api.model
    def _check_credentials(self, password, user_agent_env):
        """This is the most important and specific auth check method.

        When we get here, it means that Odoo already checked the user exists
        in this database.

        Other auth methods usually plug here.
        """
        login = self.env.user.login
        with self._auth_attempt(login):
            # Update login, just in case we stored the UID before
            attempt = self._auth_attempt_update({"login": login})
            remote = attempt.get("remote")
            # Fail if the remote is banned
            trusted = self.env["res.authentication.attempt"]._trusted(
                remote,
                login,
            )
            if not trusted:
                error = AccessDenied()
                error.reason = "banned"
                raise error
            # Continue with other auth systems
            return super(ResUsers, self)._check_credentials(password, user_agent_env)
