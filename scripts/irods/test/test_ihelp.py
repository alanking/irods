if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from . import session

class Test_ihelp(session.make_sessions_mixin([('otherrods', 'rods')], [('alice', 'apass')]), unittest.TestCase):
    def setUp(self):
        super(Test_ihelp, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_ihelp, self).tearDown()

    def test_local_ihelp(self):
        self.admin.assert_icommand('ihelp', 'STDOUT_SINGLELINE', 'The iCommands and a brief description of each:')

    def test_local_ihelp_with_help(self):
        self.admin.assert_icommand("ihelp -h", 'STDOUT_SINGLELINE', "Display iCommands synopsis")  # run ihelp with help

    def test_local_ihelp_all(self):
        self.admin.assert_icommand("ihelp -a", 'STDOUT_SINGLELINE', "Usage")  # run ihelp on all icommands

    def test_local_ihelp_with_good_icommand(self):
        self.admin.assert_icommand("ihelp ils", 'STDOUT_SINGLELINE', "Usage")  # run ihelp with good icommand

    def test_local_ihelp_with_bad_icommand(self):
        self.admin.assert_icommand_fail("ihelp idoesnotexist")  # run ihelp with bad icommand

    def test_local_ihelp_with_bad_option(self):
        self.admin.assert_icommand_fail("ihelp -z")  # run ihelp with bad option
