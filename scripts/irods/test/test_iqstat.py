from __future__ import print_function
import sys

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

from . import session
from .. import test
from ..configuration import IrodsConfig

plugin_name = IrodsConfig().default_rule_engine_plugin

class Test_Iqstat(session.make_sessions_mixin([('otherrods', 'rods')], [('alice', 'apass')]), unittest.TestCase):

    def setUp(self):
        super(Test_Iqstat, self).setUp()
        self.admin = self.admin_sessions[0]
        self.user = self.user_sessions[0]


    def tearDown(self):
        super(Test_Iqstat, self).tearDown()


    @staticmethod
    def schedule_empty_delayed_rule(session, rule_name, delay_in_seconds=10000):
        rule_map = {
            'irods_rule_engine_plugin-irods_rule_language': textwrap.dedent(f'''
                {rule_name} {{
                    delay("<PLUSET>{delay_in_seconds}</PLUSET>") {{
                        # pass
                    }}
            '''),
            'irods_rule_engine_plugin-python': textwrap.dedent(f'''
                def {rule_name}(rule_args, callback, rei):
                    callback.delayExec('<PLUSET>{delay_in_seconds}s</PLUSET>', '', '')
            ''')
        }

        session.assert_icommand(['irule', '-r', plugin_name, rule_map[plugin_name]])


    def test_iqstat_with_no_options(self):
        rule_name_user = 'test_iqstat_with_no_options_user'
        rule_name_admin = 'test_iqstat_with_no_options_admin'

        try:
            self.user.assert_icommand(['iqstat'], 'STDOUT', 'No delayed rules pending for user')
            self.admin.assert_icommand(['iqstat'], 'STDOUT', 'No delayed rules pending for user')

            schedule_empty_delayed_rule(self.user, rule_name_user)

            rc, out, err = self.user.assert_icommand(['iqstat'], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            self.admin.assert_icommand(['iqstat'], 'STDOUT', 'No delayed rules pending for user')

            schedule_empty_delayed_rule(self.admin, rule_name_admin)

            rc, out, err = self.user.assert_icommand(['iqstat'], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            rc, out, err = self.admin.assert_icommand(['iqstat'], 'STDOUT', rule_name_admin)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertNotIn(rule_name_user, out)
            self.assertIn(rule_name_admin, out)

        finally:
            self.admin.assert_icommand(['iqdel', '-a'])


    def test_iqstat_u(self):
        rule_name_user = 'test_iqstat_u_user'
        rule_name_admin = 'test_iqstat_u_admin'

        try:
            self.user.assert_icommand(['iqstat', '-u', self.user.username], 'STDOUT', 'No delayed rules pending for user')
            self.user.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', 'No delayed rules pending for user')
            self.admin.assert_icommand(['iqstat', '-u', self.user.username], 'STDOUT', 'No delayed rules pending for user')
            self.admin.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', 'No delayed rules pending for user')

            schedule_empty_delayed_rule(self.user, rule_name_user)

            rc, out, err = self.user.assert_icommand(['iqstat', '-u', self.user.username], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            rc, out, err = self.admin.assert_icommand(['iqstat', '-u', self.user.username], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            self.user.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', 'No delayed rules pending for user')
            self.admin.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', 'No delayed rules pending for user')

            schedule_empty_delayed_rule(self.admin, rule_name_admin)

            self.user.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', 'No delayed rules pending for user')

            rc, out, err = self.admin.assert_icommand(['iqstat', '-u', self.admin.username], 'STDOUT', rule_name_admin)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertNotIn(rule_name_user, out)
            self.assertIn(rule_name_admin, out)

        finally:
            self.admin.assert_icommand(['iqdel', '-a'])


    def test_iqstat_a(self):
        rule_name_user = 'test_iqstat_a_user'
        rule_name_admin = 'test_iqstat_a_admin'

        try:
            self.user.assert_icommand(['iqstat', '-a'], 'STDOUT', 'No delayed rules pending')
            self.admin.assert_icommand(['iqstat', '-a'], 'STDOUT', 'No delayed rules pending')

            schedule_empty_delayed_rule(self.user, rule_name_user)

            rc, out, err = self.user.assert_icommand(['iqstat', '-a'], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            rc, out, err = self.admin.assert_icommand(['iqstat', '-a'], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            schedule_empty_delayed_rule(self.admin, rule_name_admin)

            rc, out, err = self.user.assert_icommand(['iqstat', '-a'], 'STDOUT', rule_name_user)
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertNotIn(rule_name_admin, out)

            rc, out, err = self.admin.assert_icommand(['iqstat', '-a'], 'STDOUT', [rule_name_user, rule_name_admin])
            self.assertEqual(0, rc)
            self.assertEqual(0, err)
            self.assertIn(rule_name_user, out)
            self.assertIn(rule_name_admin, out)

        finally:
            self.admin.assert_icommand(['iqdel', '-a'])


    def test_iqstat_u_and_a(self):
        expected_error = 'Cannot use -a with -u or a specific rule ID.'
        # TODO: this should have a non-zero return code
        self.user.assert_icommand(['iqstat', '-a', '-u', self.user.username], 'STDOUT', expected_error)


    def test_iqstat_with_nonexistent_rule_id(self):
        rule_id = 1
        expected_error = f'rule \'{rule_id}\' does not exist.'
        self.user.assert_icommand(['iqstat', str(rule_id)], 'STDOUT', expected_error)


    def test_iqstat_u_with_nonexistent_user(self):
        user = 'jimbo'
        expected_error = f'User {user} does not exist.'
        # TODO: this should have a non-zero return code
        self.user.assert_icommand(['iqstat', '-u', user], 'STDOUT', expected_error)


    def test_iqstat_a_with_nonexistent_rule_id(self):
        rule_id = 1
        expected_error = 'Cannot use -a with -u or a specific rule ID.'
        # TODO: this should have a non-zero return code
        self.user.assert_icommand(['iqstat', '-a', str(rule_id)], 'STDOUT', expected_error)


    @unittest.skip('Non-string rule IDs are not currently disallowed.')
    def test_iqstat_with_nonstring_rule_id(self):
        rule_id = 'a'
        expected_error = 'Cannot use -a with -u or a specific rule ID.'
        self.user.assert_icommand(['iqstat', str(rule_id)], 'STDOUT', expected_error)
