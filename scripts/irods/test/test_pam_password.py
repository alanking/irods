from __future__ import print_function

import copy
import json
import os
import tempfile
import textwrap
import unittest

from . import session
from .. import lib
from .. import test
from ..configuration import IrodsConfig
from ..controller import IrodsController
from ..core_file import temporary_core_file
from ..test.command import assert_command


class test_set_grid_configuration(unittest.TestCase):
    def set_pam_password_config(self, option_name, option_value):
        return self.admin.assert_icommand(['iadmin', 'authentication::pam_password', option_name, option_value])

    def get_pam_password_config(self):
        options = ['password_extend_lifetime', 'password_max_time', 'password_min_time']

        return {
            o: self.admin.assert_icommand(
                ['iadmin', 'get_grid_configuration', 'authentication::pam_password', o], 'STDOUT')[1]
            for o in options}

    @classmethod
    def setUpClass(self):
        self.admin = session.mkuser_and_return_session('rodsadmin', 'otherrods', 'rods', lib.get_hostname())

        self.default_setup = {
            "password_extend_lifetime": "1",
            "password_max_time": "1209600",
            "password_min_time": "121"
        }

        self.original_configs = json.loads(self.get_pam_password_config())

        # Set the pam_password configuration values to the defaults.
        for option_name, option_value in self.default_setup.items():
            self.set_pam_password_config(option_name, option_value)

    @classmethod
    def tearDownClass(self):
        # Put everything back to the original configuration settings.
        for option_name, option_value in self.original_configs.items():
            self.set_pam_password_config(option_name, option_value)

        with session.make_session_for_existing_admin() as admin_session:
            self.admin.__exit__()
            admin_session.assert_icommand(['iadmin', 'rmuser', self.admin.username])
