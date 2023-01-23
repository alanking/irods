import time
import sys
import shutil
import os
import socket
import datetime
import imp
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from .. import test
from . import settings
from . import session
from .. import lib
from ..configuration import IrodsConfig
from . import resource_suite

class Test_DeferredToDeferred(resource_suite.ResourceBase, unittest.TestCase):

    def setUp(self):
        with session.make_session_for_existing_admin() as admin_session:
            context_prefix = lib.get_hostname() + ':' + IrodsConfig().irods_directory
            admin_session.assert_icommand('iadmin modresc demoResc name origResc', 'STDOUT_SINGLELINE', 'rename', input='yes\n')
            admin_session.assert_icommand('iadmin mkresc demoResc deferred', 'STDOUT_SINGLELINE', 'deferred')
            admin_session.assert_icommand('iadmin mkresc defResc1 deferred', 'STDOUT_SINGLELINE', 'deferred')
            admin_session.assert_icommand('iadmin mkresc defResc2 deferred', 'STDOUT_SINGLELINE', 'deferred')
            admin_session.assert_icommand('iadmin mkresc defResc3 deferred', 'STDOUT_SINGLELINE', 'deferred')
            admin_session.assert_icommand('iadmin mkresc defResc4 deferred', 'STDOUT_SINGLELINE', 'deferred')
            admin_session.assert_icommand('iadmin mkresc rescA "unixfilesystem" ' + context_prefix + '/rescAVault', 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand('iadmin mkresc rescB "unixfilesystem" ' + context_prefix + '/rescBVault', 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand('iadmin addchildtoresc defResc3 rescA')
            admin_session.assert_icommand('iadmin addchildtoresc defResc4 rescB')
            admin_session.assert_icommand('iadmin addchildtoresc demoResc defResc1')
            admin_session.assert_icommand('iadmin addchildtoresc demoResc defResc2')
            admin_session.assert_icommand('iadmin addchildtoresc defResc1 defResc3')
            admin_session.assert_icommand('iadmin addchildtoresc defResc2 defResc4')
        super(Test_DeferredToDeferred, self).setUp()

    def tearDown(self):
        super(Test_DeferredToDeferred, self).tearDown()
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand("iadmin rmchildfromresc defResc3 rescA")
            admin_session.assert_icommand("iadmin rmchildfromresc defResc4 rescB")
            admin_session.assert_icommand("iadmin rmchildfromresc defResc1 defResc3")
            admin_session.assert_icommand("iadmin rmchildfromresc defResc2 defResc4")
            admin_session.assert_icommand("iadmin rmchildfromresc demoResc defResc1")
            admin_session.assert_icommand("iadmin rmchildfromresc demoResc defResc2")
            admin_session.assert_icommand("iadmin rmresc rescA")
            admin_session.assert_icommand("iadmin rmresc rescB")
            admin_session.assert_icommand("iadmin rmresc defResc1")
            admin_session.assert_icommand("iadmin rmresc defResc2")
            admin_session.assert_icommand("iadmin rmresc defResc3")
            admin_session.assert_icommand("iadmin rmresc defResc4")
            admin_session.assert_icommand("iadmin rmresc demoResc")
            admin_session.assert_icommand("iadmin modresc origResc name demoResc", 'STDOUT_SINGLELINE', 'rename', input='yes\n')
        irods_config = IrodsConfig()
        shutil.rmtree(irods_config.irods_directory + "/rescAVault", ignore_errors=True)
        shutil.rmtree(irods_config.irods_directory + "/rescBVault", ignore_errors=True)

    @unittest.skipIf(test.settings.TOPOLOGY_FROM_RESOURCE_SERVER, "Skip for topology testing from resource server")
    def test_iput_irm(self):
            # =-=-=-=-=-=-=-
            # build a logical path for putting a file
            test_file = self.admin.session_collection + "/test_file.txt"

            # =-=-=-=-=-=-=-
            # put a test_file.txt - should be on rescA given load table values
            self.admin.assert_icommand("iput -f %s %s" % (self.testfile, test_file))
            self.admin.assert_icommand("irm -f " + test_file)


class test_configuring_operations_to_fail(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.user = session.mkuser_and_return_session('rodsuser', 'alice', 'apass', lib.get_hostname())


    @classmethod
    def tearDownClass(self):
        with session.make_session_for_existing_admin() as admin_session:
            self.user.__exit__()
            admin_session.run_icommand(['iadmin', 'rmuser', 'alice'])


#   operation_names = [
#       'resource_create',
#       'resource_open',
#       'resource_read',
#       'resource_write',
#       'resource_close',
#       'resource_unlink',
#       'resource_stat',
#       'resource_fstat',
#       'resource_fsync',
#       'resource_mkdir',
#       'resource_chmod',
#       'resource_opendir',
#       'resource_readdir',
#       'resource_rename',
#       'resource_freespace',
#       'resource_lseek',
#       'resource_rmdir',
#       'resource_closedir',
#       'resource_truncate',
#       'resource_stagetocache',
#       'resource_synctoarch',
#       'resource_registered',
#       'resource_unregistered',
#       'resource_modified',
#       'resource_resolve_hierarchy',
#       'resource_rebalance',
#       'resource_notify']


    def test_operation_close_failure_on_data_object_creation__issue_6154(self):
        contents = 'munge_operations=resource_close'
        filename = 'test_operation_close_fails_on_data_object_creation__issue_6154'
        logical_path = os.path.join(self.user.session_collection, filename)
        local_file = os.path.join(self.user.local_session_dir, filename)
        file_size_in_bytes = 10

        target_resource = 'test_configuring_operations_to_fail_resource'

        with session.make_session_for_existing_admin() as admin_session:
            try:
                lib.make_file(local_file, file_size_in_bytes)
                lib.create_ufs_resource(target_resource, admin_session)

                # Successfully create a new data object, targeting target_resource
                self.user.assert_icommand(['iput', '-R', target_resource, local_file, logical_path])
                self.assertTrue(lib.replica_exists(self.user, logical_path, 0))
                self.assertEqual(str(1), lib.get_replica_status(self.user, os.path.basename(logical_path), 0))

                # Configure the resource such that resource close operations fail
                admin_session.assert_icommand(['iadmin', 'modresc', target_resource, 'context', contents])

                # Try to overwrite the existing replica and observe the failure
                self.user.assert_icommand(['iput', '-f', '-R', target_resource, local_file, logical_path],
                                          'STDERR', 'PLUGIN_OPERATION_CONFIGURED_TO_FAIL')
                self.assertTrue(lib.replica_exists(self.user, logical_path, 0))
                self.assertEqual(str(0), lib.get_replica_status(self.user, os.path.basename(logical_path), 0))

            finally:
                admin_session.assert_icommand(['iadmin', 'modresc', target_resource, 'context', 'null'])
                lib.set_replica_status(admin_session, logical_path, 0, 0)

                self.user.assert_icommand(['irm', '-f', logical_path])

                lib.remove_resource(target_resource, admin_session)


    def test_operation_stat_failure_on_data_object_creation__issue_6479(self):
        context_string = 'munge_operations=resource_stat'
        filename = 'test_operation_stat_failure_on_data_object_creation__issue_6479'
        logical_path = os.path.join(self.user.session_collection, filename)
        local_file = os.path.join(self.user.local_session_dir, filename)
        file_size_in_bytes = 10

        target_resource = 'test_configuring_operations_to_fail_resource'

        with session.make_session_for_existing_admin() as admin_session:
            try:
                lib.make_file(local_file, file_size_in_bytes)
                lib.create_ufs_resource(target_resource, admin_session)

                # Successfully create a new data object, targeting target_resource
                self.user.assert_icommand(['iput', '-R', target_resource, local_file, logical_path])
                self.assertTrue(lib.replica_exists(self.user, logical_path, 0))
                self.assertEqual(str(1), lib.get_replica_status(self.user, os.path.basename(logical_path), 0))

                # Configure the resource such that resource stat operations fail
                admin_session.assert_icommand(['iadmin', 'modresc', target_resource, 'context', context_string])

                # Try to overwrite the existing replica and observe the failure
                self.user.assert_icommand(['iput', '-f', '-R', target_resource, local_file, logical_path],
                                          'STDERR', 'PLUGIN_OPERATION_CONFIGURED_TO_FAIL')
                self.assertTrue(lib.replica_exists(self.user, logical_path, 0))
                self.assertEqual(str(0), lib.get_replica_status(self.user, os.path.basename(logical_path), 0))

            finally:
                admin_session.assert_icommand(['iadmin', 'modresc', target_resource, 'context', 'null'])
                lib.set_replica_status(admin_session, logical_path, 0, 0)

                self.user.assert_icommand(['irm', '-f', logical_path])

                lib.remove_resource(target_resource, admin_session)
