if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from . import session

class Test_iexit(session.make_sessions_mixin([('otherrods', 'rods')], [('alice', 'apass')]), unittest.TestCase):
    def setUp(self):
        super(Test_iexit, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_iexit, self).tearDown()

    def test_iexit(self):
        self.admin.assert_icommand("iexit")  # just go home

    def test_iexit_verbose(self):
        self.admin.assert_icommand("iexit -v", 'STDOUT_SINGLELINE', "Deleting (if it exists) session envFile:")  # home, verbose

    def test_iexit_with_bad_option(self):
        self.admin.assert_icommand_fail("iexit -z")  # run iexit with bad option

    def test_iexit_with_bad_parameter(self):
        self.admin.assert_icommand_fail("iexit badparameter")  # run iexit with bad parameter

