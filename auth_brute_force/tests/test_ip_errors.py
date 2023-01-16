# Copyright 2017 Tecnativa - Jairo Llopis
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from unittest.mock import patch

from odoo import http
from odoo.exceptions import AccessDenied
from odoo.tests.common import tagged
from odoo.tools import mute_logger

from ..models import res_authentication_attempt, res_users
from .common import CommonTests, logging, skip_unless_addons_installed

_logger = logging.getLogger(__name__)

GARBAGE_LOGGERS = (
    "werkzeug",
    res_authentication_attempt.__name__,
    res_users.__name__,
)


# Skip CSRF validation on tests
@patch(http.__name__ + ".WebRequest.validate_csrf", return_value=True)
# Skip specific browser forgery on redirections
# @patch(http.__name__ + ".redirect_with_hash", side_effect=redirect)
# Faster tests without calls to geolocation API
# @patch(res_authentication_attempt.__name__ + ".urlopen", return_value="")
@tagged("post_install", "-at_install")
class RemoteAddressCheck(CommonTests):

    # @skip_unless_addons_installed("web")
    @mute_logger(*GARBAGE_LOGGERS)
    def test_login_with_wrong_ip(self, *args):
        """Remove from whitelist and try login."""
        data1 = {
            "login": "test_user",  # Wrong
            "password": "1234",
        }
        with self.cursor() as cr:
            env = self.env(cr)
            # Fail 3 times
            with self.assertRaises(AccessDenied):
                env["res.users"].authenticate(
                    cr.dbname,
                    data1["login"],
                    data1["password"],
                    {"interactive": True},
                )
            for _ in range(2):
                try:
                    env["res.users"].authenticate(
                        cr.dbname,
                        data1["login"],
                        data1["password"],
                        {"interactive": True},
                    )
                except AccessDenied:
                    # _logger.info("AccessError with login: {}".format(data1['login']))
                    continue
            # Create a new fake request with `demo` as IP address
            self.create_fake_request("demo")
            # Try to login with `demo` ip
            try:
                env["res.users"].authenticate(
                    cr.dbname, data1["login"], data1["password"], {"interactive": True}
                )
            except AccessDenied:
                _logger.info("AccessError with login: {}".format(data1["login"]))
            #  Check metadata of remote address
            failed = env["res.authentication.attempt"].search([])

            # Add ip=`demo` to whitelist and check again we will get True this time.
            failed.action_whitelist_add()
            self.assertTrue(
                env["res.authentication.attempt"]._trusted(
                    "demo",
                    data1["login"],
                ),
            )
            # Remove check_remote parameter
            self.env["ir.config_parameter"].set_param(
                "auth_brute_force.check_remote", "False"
            )
            # It will return either True or False that's why bool instance check
            # self.assertFalse(all(failed.mapped('remote_metadata')))
            self.assertIsInstance(all(failed.mapped("remote_metadata")), bool)

    @mute_logger(*GARBAGE_LOGGERS)
    def test_login_without_ip(self, *args):
        data1 = {
            "login": "test_user",  # Wrong
            "password": "1234",
        }
        with self.cursor() as cr:
            env = self.env(cr)
            # Fail 3 times
            # Create new fake request without ip
            self.create_fake_request(False)
            # Try to login
            with self.assertRaises(AccessDenied):
                env["res.users"].authenticate(
                    cr.dbname, data1["login"], data1["password"], {"interactive": True}
                )

    @skip_unless_addons_installed("web-2")
    def test_check_decorator(self, *args):
        """skip_unless_addons_installed checking with wrong module name"""
