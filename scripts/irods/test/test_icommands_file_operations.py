import sys
if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest
import contextlib
import copy
import errno
import inspect
import json
import logging
import os
import tempfile
import time
import shutil
import re

from ..configuration import IrodsConfig
from ..controller import IrodsController
from ..core_file import temporary_core_file
from .. import paths
from .. import test
from .. import lib
from . import resource_suite
from . import ustrings
from .rule_texts_for_tests import rule_texts


@unittest.skipIf(test.settings.TOPOLOGY_FROM_RESOURCE_SERVER, "Skip for topology testing from resource server")
class Test_ICommands_File_Operations(resource_suite.ResourceBase, unittest.TestCase):
    plugin_name = IrodsConfig().default_rule_engine_plugin
    class_name = 'Test_ICommands_File_Operations'

    def setUp(self):
        super(Test_ICommands_File_Operations, self).setUp()
        self.testing_tmp_dir = '/tmp/irods-test-icommands-recursive'
        shutil.rmtree(self.testing_tmp_dir, ignore_errors=True)
        os.mkdir(self.testing_tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.testing_tmp_dir)
        super(Test_ICommands_File_Operations, self).tearDown()

    def iput_r_large_collection(self, user_session, base_name, file_count, file_size):
        local_dir = os.path.join(self.testing_tmp_dir, base_name)
        local_files = lib.make_large_local_tmp_dir(local_dir, file_count, file_size)
        user_session.assert_icommand(['iput', '-r', local_dir], "STDOUT_SINGLELINE", ustrings.recurse_ok_string())
        rods_files = set(user_session.get_entries_in_collection(base_name))
        self.assertTrue(set(local_files) == rods_files,
                        msg="Files missing:\n" + str(set(local_files) - rods_files) + "\n\n" +
                            "Extra files:\n" + str(rods_files - set(local_files)))
        vault_files = set(os.listdir(os.path.join(user_session.get_vault_session_path(), base_name)))
        self.assertTrue(set(local_files) == vault_files,
                        msg="Files missing from vault:\n" + str(set(local_files) - vault_files) + "\n\n" +
                            "Extra files in vault:\n" + str(vault_files - set(local_files)))
        return (local_dir, local_files)

    def test_iput_r(self):
        self.iput_r_large_collection(self.user0, "test_iput_r_dir", file_count=1000, file_size=100)

    def test_irm_r(self):
        base_name = "test_irm_r_dir"
        self.iput_r_large_collection(self.user0, base_name, file_count=1000, file_size=100)

        self.user0.assert_icommand("irm -r " + base_name, "EMPTY")
        self.user0.assert_icommand("ils " + base_name, 'STDERR_SINGLELINE', "does not exist")

        vault_files_post_irm = os.listdir(os.path.join(self.user0.get_vault_session_path(),
                                                       base_name))
        self.assertTrue(len(vault_files_post_irm) == 0,
                        msg="Files not removed from vault:\n" + str(vault_files_post_irm))

    def test_irm_rf_nested_coll(self):
        # test settings
        depth = 50
        files_per_level = 5
        file_size = 5

        # make local nested dirs
        coll_name = "test_irm_r_nested_coll"
        local_dir = os.path.join(self.testing_tmp_dir, coll_name)
        local_dirs = lib.make_deep_local_tmp_dir(local_dir, depth, files_per_level, file_size)

        # iput dir
        self.user0.assert_icommand("iput -r {local_dir}".format(**locals()), "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

        # force remove collection
        self.user0.assert_icommand("irm -rf {coll_name}".format(**locals()), "EMPTY")
        self.user0.assert_icommand("ils {coll_name}".format(**locals()), 'STDERR_SINGLELINE', "does not exist")

        # make sure no files are left in the vault
        user_vault_dir = os.path.join(self.user0.get_vault_session_path(), coll_name)
        out, _ = lib.execute_command('find {user_vault_dir} -type f'.format(**locals()))
        self.assertEqual(out, '')

    def test_iput_r_with_kw(self):
        # test settings
        depth = 50
        files_per_level = 5
        file_size = 5

        # make local nested dirs
        coll_name = "test_iput_r_with_kw"
        local_dir = os.path.join(self.testing_tmp_dir, coll_name)
        local_dirs = lib.make_deep_local_tmp_dir(local_dir, depth, files_per_level, file_size)

        try:
            # load server_config.json to inject new settings
            server_config_filename = paths.server_config_path()
            with open(server_config_filename) as f:
                svr_cfg = json.load(f)
            svr_cfg['log_level']['resource'] = 'debug'

            # dump to a string to repave the existing server_config.json
            new_server_config = json.dumps(svr_cfg, sort_keys=True, indent=4, separators=(',', ': '))
            with lib.file_backed_up(server_config_filename):
                # repave the existing server_config.json
                with open(server_config_filename, 'w') as f:
                    f.write(new_server_config)

                IrodsController().reload_configuration()

                # get log offset
                initial_size_of_server_log = lib.get_file_size_by_path(IrodsConfig().server_log_path)

                # iput dir
                self.user0.assert_icommand("iput -r {local_dir}".format(**locals()), "STDOUT_SINGLELINE", ustrings.recurse_ok_string())
                self.user0.assert_icommand('iquest "SELECT COUNT(DATA_ID) WHERE COLL_NAME LIKE \'%/{coll_name}%\'"'.format(**locals()), 'STDOUT', str(files_per_level * depth))

                # look for occurrences of debug sequences in the log
                rec_op_kw_string = 'recursiveOpr found in cond_input for file_obj'
                lib.delayAssert(
                    lambda: lib.log_message_occurrences_equals_count(
                        msg=rec_op_kw_string,
                        count=files_per_level * depth,
                        server_log_path=IrodsConfig().server_log_path,
                        start_index=initial_size_of_server_log))

        finally:
            IrodsController().restart()

    def test_imv_r(self):
        base_name_source = "test_imv_r_dir_source"
        file_names = set(self.iput_r_large_collection(
            self.user0, base_name_source, file_count=1000, file_size=100)[1])

        base_name_target = "test_imv_r_dir_target"
        self.user0.assert_icommand("imv " + base_name_source + " " + base_name_target, "EMPTY")
        self.user0.assert_icommand("ils " + base_name_source, 'STDERR_SINGLELINE', "does not exist")
        self.user0.assert_icommand("ils", 'STDOUT_SINGLELINE', base_name_target)
        rods_files_post_imv = set(self.user0.get_entries_in_collection(base_name_target))
        self.assertTrue(file_names == rods_files_post_imv,
                        msg="Files missing:\n" + str(file_names - rods_files_post_imv) + "\n\n" +
                            "Extra files:\n" + str(rods_files_post_imv - file_names))

        vault_files_post_irm_source = set(os.listdir(os.path.join(self.user0.get_vault_session_path(),
                                                                  base_name_source)))
        self.assertTrue(len(vault_files_post_irm_source) == 0)

        vault_files_post_irm_target = set(os.listdir(os.path.join(self.user0.get_vault_session_path(),
                                                                  base_name_target)))
        self.assertTrue(file_names == vault_files_post_irm_target,
                        msg="Files missing from vault:\n" + str(file_names - vault_files_post_irm_target) + "\n\n" +
                            "Extra files in vault:\n" + str(vault_files_post_irm_target - file_names))

    def test_iput_bulk_check_acpostprocforput__2841(self):
        # prepare test directory
        number_of_files = 5
        dirname = self.admin.local_session_dir + '/files'
        # files less than 4200000 were failing to trigger the writeLine
        for filesize in range(5000, 6000000, 500000):
            lib.make_large_local_tmp_dir(dirname, number_of_files, filesize)
            # manipulate core.re and check the server log
            with temporary_core_file() as core:
                time.sleep(1)  # remove once file hash fix is committed #2279
                core.add_rule(rule_texts[self.plugin_name][self.class_name][inspect.currentframe().f_code.co_name])
                time.sleep(1)  # remove once file hash fix is committed #2279

                initial_size_of_server_log = lib.get_file_size_by_path(paths.server_log_path())
                self.admin.assert_icommand(['iput', '-frb', dirname], "STDOUT_SINGLELINE", ustrings.recurse_ok_string())
                lib.delayAssert(
                    lambda: lib.log_message_occurrences_equals_count(
                        msg='writeLine: inString = acPostProcForPut called for',
                        count=number_of_files,
                        start_index=initial_size_of_server_log))
                shutil.rmtree(dirname)

    def test_large_irods_maximum_size_for_single_buffer_in_megabytes_2880(self):
        self.admin.environment_file_contents['irods_maximum_size_for_single_buffer_in_megabytes'] = 2000
        with tempfile.NamedTemporaryFile(prefix='test_large_irods_maximum_size_for_single_buffer_in_megabytes_2880') as f:
            lib.make_file(f.name, 800*1000*1000, contents='arbitrary')
            self.admin.assert_icommand(['iput', f.name, '-v'], 'STDOUT_SINGLELINE', '0 thr')

    def test_igetwild_with_semicolon_in_filename(self):

        localfile = 'thelocalfile.txt'
        localpath = lib.create_local_testfile(localfile)
        badfiles = ['; touch oops', '\;\ touch\ oops']
        counter = 0
        for badname in badfiles:
            counter = counter + 1
            print("====================[{0}of{1}]=[{2}]===================".format(counter, len(badfiles), badname))
            badpath = lib.create_local_testfile(badname)
            os.unlink(badpath)
            self.user0.assert_icommand(['imkdir', 'subdir'])
            self.user0.assert_icommand(['ils', '-rL', 'subdir/'+badname], 'STDERR_SINGLELINE', 'does not exist')
            self.user0.assert_icommand(['iput', localfile, 'subdir/'+badname])
            self.user0.assert_icommand(['ils', '-rL'], 'STDOUT_SINGLELINE', 'subdir/'+badname)
            self.user0.assert_icommand(['ils', '-L', 'oops'], 'STDERR_SINGLELINE', 'does not exist')
            self.user0.assert_icommand(['igetwild', self.user0.session_collection+'/subdir', 'oops', 'e'], 'STDOUT_SINGLELINE', badname)
            assert os.path.isfile(badpath)
            assert not os.path.isfile(os.path.join(self.user0.session_collection, 'oops'))
            self.user0.assert_icommand(['irm', '-rf', 'subdir'])
            os.unlink(badpath)
        os.unlink(localpath)

    def test_irm_colloprstat__3572(self):
        collection_to_delete = 'collection_to_delete'
        self.admin.assert_icommand(['imkdir', collection_to_delete])
        filename = 'test_irm_colloprstat__3572'
        lib.make_file(filename, 50)
        for i in range(10):
            self.admin.assert_icommand(['iput', filename, '{0}/file_{1}'.format(collection_to_delete, str(i))])

        initial_size_of_server_log = lib.get_file_size_by_path(paths.server_log_path())
        self.admin.assert_icommand(['irm', '-rf', collection_to_delete])
        lib.delayAssert(
            lambda: lib.log_message_occurrences_equals_count(
                msg='ERROR',
                count=0,
                start_index=initial_size_of_server_log))
        os.unlink(filename)

    ##################################
    # Issue - 3997:
    # This tests the functionality of irsync and iput, with a single source directory
    # and a target collection which does not pre-exist.
    ########
    def test_target_not_exist_singlesource_3997(self):

        ##################################
        # All cases listed below create identical results: target 'dir1' is created.
        ########
        test_cases = [
                        'iput -r {dir1path}',
                        'iput -r {dir1path} {target1}',
                        'irsync -r {dir1path} i:{target1}'
        ]

        base_name = 'target_not_exist_singlesource_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = dir1
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:
                cmd = cmdstring.format(**locals())

                ##################################
                # Target collection exists or not based on runimkdir
                # Single source directory command
                # This means that the contents of dir1 will be
                # placed directly under target_collection (recursively).
                ########

                self.user0.assert_icommand(cmd, "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

                self.user0.assert_icommand( 'ils {target1}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '/{target1}/subdir1'.format(**locals()) ])

                self.user0.assert_icommand( 'ils {target1}/subdir1'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                        [ '  0', '  1' ])

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                # Just to be paranoid, make sure it's really gone
                self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)


    ##################################
    # Issue - 3997:
    # This tests the functionality of iput, with a single source directory
    # and a target collection which does pre-exist.
    ########
    def test_iput_target_does_exist_singlesource_3997(self):

        ##################################
        # All cases listed below create identical results
        # (leaving this in list form, in case additional cases show up).
        ########
        test_cases = [
                        'iput -r {dir1path} {target1}',
        ]

        base_name = 'iput_target_does_exist_singlesource_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:

                # Create the pre-existing collection
                self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                cmd = cmdstring.format(**locals())

                ##################################
                # Target collection exists
                # Single source directory command
                # This means that the contents of dir1 will be
                # placed directly under target_collection (recursively).
                ########

                self.user0.assert_icommand(cmd, "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

                # Command creates source dir under existing collection
                self.user0.assert_icommand( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', dir1 )

                self.user0.assert_icommand( 'ils {target1}/{dir1}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '/{target1}/{dir1}/subdir1'.format(**locals()) ])

                self.user0.assert_icommand( 'ils {target1}/{dir1}/subdir1'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                        [ '  0', '  1' ])

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                # Just to be paranoid, make sure it's really gone
                self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)


    ##################################
    # Issue - 3997:
    # This tests the functionality of irsync with a single source directory
    # and a target collection which does pre-exist.
    ########
    def test_irsync_target_does_exist_singlesource_3997(self):

        ##################################
        # All cases listed below create identical results
        # (leaving this in list form, in case additional cases show up).
        ########
        test_cases = [
                        'irsync -r {dir1path} i:{target1}'
        ]

        base_name = 'irsync_target_does_exist_singlesource_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:

                # Create the pre-existing collection
                self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                cmd = cmdstring.format(**locals())

                ##################################
                # Target collection exists
                # Single source directory command
                # This means that the contents of dir1 will be
                # placed directly under target_collection (recursively).
                ########

                self.user0.assert_icommand(cmd, "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

                self.user0.assert_icommand( 'ils {target1}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '/{target1}/subdir1'.format(**locals()) ])

                self.user0.assert_icommand( 'ils {target1}/subdir1'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                        [ '  0', '  1' ])

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                # Just to be paranoid, make sure it's really gone
                self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)

    ##################################
    # Issue - 3997:
    # This tests the functionality of irsync and iput with multiple source directories
    # and a target collection which first does not exist, but then does (the testcases are run twice).
    ########
    def test_multiple_source_3997(self):

        ##################################
        # All cases listed below create identical results.
        # The test cases are run twice each - with and without an imkdir first.
        ########
        test_cases = [
                        'iput -r {dir1path} {dir2path} {target1}',
                        'irsync -r {dir1path} {dir2path} i:{target1}',
        ]

        base_name = 'multiple_source_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir2 = 'dir2'
            dir1path = os.path.join(local_dir, dir1)
            dir2path = os.path.join(local_dir, dir2)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = dir1
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(dir2path,4)     # Four files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:
                cmd = cmdstring.format(**locals())

                for runimkdir in [ 'no', 'yes' ]:

                    if runimkdir == 'yes':
                        self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                    self.user0.assert_icommand(cmd, "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

                    # Command creates source dir under existing collection
                    self.user0.assert_icommand( 'ils {target1}'.format(**locals()), 'STDOUT_MULTILINE', [ dir1, dir2 ] )

                    self.user0.assert_icommand( 'ils {target1}/{dir1}'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                                [ '  0', '  1', '/{target1}/{dir1}/subdir1'.format(**locals()) ])

                    self.user0.assert_icommand( 'ils {target1}/{dir1}/subdir1'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                                [ '  0', '  1' ])

                    self.user0.assert_icommand( 'ils {target1}/{dir2}'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                                [ '  0', '  1', ' 2', ' 3' ] )

                    self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                    # Just to be paranoid, make sure it's really gone
                    self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)
            shutil.rmtree(os.path.abspath(dir2path), ignore_errors=True)


    ##################################
    # Issue - 3997:
    # This tests the functionality of icp, with a single collection
    # and a target collection which does not pre-exist.
    ########
    def test_icp_target_not_exist_singlesource_3997(self):

        ##################################
        # All cases listed below create identical results
        ########
        test_cases = [
                        'icp -r {dir1} {target1}'
        ]

        base_name = 'icp_target_not_exist_singlesource_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:

                # This will create everything under collection dir1
                self.user0.run_icommand('iput -r {dir1path}'.format(**locals()))

                cmd = cmdstring.format(**locals())

                ##################################
                # Target collection exists or not based on runimkdir
                # Single source directory command
                # This means that the contents of dir1 will be
                # placed directly under target_collection (recursively).
                ########

                # Successful icp is silent
                self.user0.assert_icommand(cmd, "EMPTY")

                self.user0.assert_icommand( 'ils {target1}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '/{target1}/subdir1'.format(**locals()) ])

                self.user0.assert_icommand( 'ils {target1}/subdir1'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                        [ '  0', '  1' ])

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                # Just to be paranoid, make sure it's really gone
                self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)

    ##################################
    # Issue - 3997:
    # This tests the functionality of icp, with a single collection
    # and a target collection which does not pre-exist.
    ########
    def test_icp_target_does_exist_singlesource_3997(self):

        ##################################
        # All cases listed below create identical results
        ########
        test_cases = [
                        'icp -r {dir1} {target1}'
        ]

        base_name = 'icp_target_does_exist_singlesource_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:

                # This will create the target collection 'target1'
                self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                # This will create everything under collection dir1
                self.user0.run_icommand('iput -r {dir1path}'.format(**locals()))

                cmd = cmdstring.format(**locals())

                ##################################
                # Target collection exists or not based on runimkdir
                # Single source directory command
                # This means that the contents of dir1 will be
                # placed directly under target_collection (recursively).
                ########

                # Successful icp is silent
                self.user0.assert_icommand(cmd, "EMPTY")

                # Command creates source dir under existing collection
                self.user0.assert_icommand( 'ils {target1}'.format(**locals()), 'STDOUT_MULTILINE', dir1 )

                self.user0.assert_icommand( 'ils {target1}/{dir1}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '/{target1}/{dir1}/subdir1'.format(**locals()) ])

                self.user0.assert_icommand( 'ils {target1}/{dir1}/subdir1'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                        [ '  0', '  1' ])

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                # Just to be paranoid, make sure it's really gone
                self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)


    ##################################
    # Issue - 3997:
    # This tests the functionality of icp, with a single collection
    # and a target collection. Each case is run twice - once without preexisting
    # target collection, and once after using imkdir to create the collection.
    ########
    def test_icp_multiple_src_3997(self):

        ##################################
        # All cases listed below create identical results
        ########
        test_cases = [
                        'icp -r {dir1} {dir2} {target1}'
        ]

        base_name = 'icp_multiple_src_3997'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            dir1 = 'dir1'
            dir2 = 'dir2'
            dir1path = os.path.join(local_dir, dir1)
            dir2path = os.path.join(local_dir, dir2)
            subdir1 = os.path.join(dir1path, 'subdir1')
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(dir2path,4)     # Four files in this one
            lib.create_directory_of_small_files(subdir1path,2)      # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            for cmdstring in test_cases:
                for runimkdir in [ 'no', 'yes' ]:

                    if runimkdir == 'yes':
                        self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                    # This will create all data objects under collections dir1 and dir2
                    self.user0.run_icommand('iput -r {dir1path}'.format(**locals()))
                    self.user0.run_icommand('iput -r {dir2path}'.format(**locals()))

                    cmd = cmdstring.format(**locals())

                    ##################################
                    # Target collection exists or not based on runimkdir
                    # Single source directory command
                    # This means that the contents of dir1 will be
                    # placed directly under target_collection (recursively).
                    ########

                    # Successful icp is silent
                    self.user0.assert_icommand(cmd, "EMPTY")

                    # Command creates source dir under existing collection
                    self.user0.assert_icommand( 'ils {target1}'.format(**locals()), 'STDOUT_MULTILINE', [ dir1, dir2 ] )

                    self.user0.assert_icommand( 'ils {target1}/{dir1}'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                                [ '  0', '  1', '/{target1}/{dir1}/subdir1'.format(**locals()) ])

                    self.user0.assert_icommand( 'ils {target1}/{dir2}'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                                [ '  0', '  1', '  2', '  3' ] )

                    self.user0.assert_icommand( 'ils {target1}/{dir1}/subdir1'.format(**locals()),
                                                'STDOUT_MULTILINE',
                                            [ '  0', '  1' ])

                    self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

                    # Just to be paranoid, make sure it's really gone
                    self.user0.assert_icommand_fail( 'ils {target1}'.format(**locals()), 'STDOUT_SINGLELINE', target1 )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)


    #################################################################
    # Issue 4006 - can no longer have regular files on the command line
    # when the -r flag is specified
    #############################
    def test_irsync_iput_file_dir_mix_with_recursive_4006(self):

        base_name = 'irsync_iput_file_dir_mix_with_recursive_4006'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            ##################################
            # Setup
            ########
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = 'subdir1'
            subdir1path = os.path.join(dir1path, subdir1)
            dir2 = 'dir2'
            dir2path = os.path.join(local_dir, dir2)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,4)  # Four files in this one
            lib.create_directory_of_small_files(dir2path,2)     # Two files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            ##################################
            # Grouped tests (should) produce the same behavior and results:
            ########
            test_cases = [
                            'iput -r {dir1path}/0 {subdir1path} {target1}',
                            'irsync -r {dir1path}/0 {subdir1path} i:{target1}',
                            'iput -r {dir2path} {dir1path}/0 {subdir1path} {target1}',
                            'irsync -r {dir2path} {dir1path}/0 {subdir1path} i:{target1}',
                         ]

            ##################################
            # Mix directories and files should fail with nothing created in irods
            ########
            for cmdstring in test_cases:

                cmd = cmdstring.format(**locals())
                self.user0.assert_icommand(cmd, "STDERR_SINGLELINE", 'ERROR: disallow_file_dir_mix_on_command_line: Cannot include regular file')
                self.user0.assert_icommand_fail( 'ils {target1path}'.format(**locals()), 'STDOUT_SINGLELINE', '{target1}'.format(**locals()) )

                # Create the pre-existing collection
                # self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

            ##################################
            # Grouped tests (should) produce the same behavior and results:
            ########
            test_cases = [
                            'iput {dir1path}/0 {dir1path}/1 {target1}',
                            'irsync {dir1path}/0 {dir1path}/1 i:{target1}',
                         ]

            ##################################
            # Transfer of multiple regular files to a target requires pre-existing target
            ########
            for cmdstring in test_cases:

                cmd = cmdstring.format(**locals())
                _,stderr,_ = self.user0.run_icommand(cmd)

                estr = 'ERROR: resolveRodsTarget: target {target1path} does not exist status = -310000 USER_FILE_DOES_NOT_EXIST'.format(**locals())
                self.assertIn(estr, stderr, '{cmd}: Expected stderr: "...{estr}...", got: "{stderr}"'.format(**locals()))

                self.user0.assert_icommand_fail( 'ils {target1path}'.format(**locals()), 'STDOUT_SINGLELINE', '{target1}'.format(**locals()) )

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)
            shutil.rmtree(os.path.abspath(dir2path), ignore_errors=True)

    #################################################################
    # Issue 4048 - irsync was not transferring regular files when specified
    # on the command line. When the regular files were inside directories, it
    # was ok.  We are checking both irsync and iput for consistency.
    #############################
    def test_irsync_iput_regular_files_only_4048(self):

        base_name = 'irsync_iput_regular_files_only_4048'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            ##################################
            # Setup
            ########
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = 'subdir1'
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = 'target1'
            target1path='{self.user0.session_collection}/{target1}'.format(**locals())

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,4)  # Four files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            ##################################
            # Grouped tests (should) produce the same behavior and results:
            ########
            test_cases = [
                            'irsync {dir1path}/0 {dir1path}/1 {subdir1path}/2 i:{target1}',
                            'iput {dir1path}/0 {dir1path}/1 {subdir1path}/2 {target1}',
                         ]

            ##################################
            # Transfer of multiple regular files to a target requires pre-existing target
            # This first try should fail for all test cases
            ########
            for cmdstring in test_cases:

                cmd = cmdstring.format(**locals())
                _,stderr,_ = self.user0.run_icommand(cmd)

                estr = 'ERROR: resolveRodsTarget: target {target1path} does not exist status = -310000 USER_FILE_DOES_NOT_EXIST'.format(**locals())
                self.assertIn(estr, stderr, '{cmd}: Expected stderr: "...{estr}...", got: "{stderr}"'.format(**locals()))

                self.user0.assert_icommand_fail( 'ils {target1path}'.format(**locals()), 'STDOUT_SINGLELINE', '{target1}'.format(**locals()) )

            ##################################
            # Transfer of multiple regular files to a target requires pre-existing target
            # This time we'll create the target collection first
            ########
            for cmdstring in test_cases:

                self.user0.run_icommand('imkdir -p {target1path}'.format(**locals()))

                cmd = cmdstring.format(**locals())
                self.user0.assert_icommand(cmd, "EMPTY")

                self.user0.assert_icommand( 'ils {target1path}'.format(**locals()),
                                            'STDOUT_MULTILINE',
                                            [ '  0', '  1', '  2' ] )

                self.user0.run_icommand('irm -rf {target1path}'.format(**locals()))

        finally:
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)



    #################################################################
    # Issue 4030 - failure to write to collection path "/" was providing
    # insufficient detail in the error message to the user.
    #############################
    def test_writing_collection_under_slash_4030(self):

        base_name = 'writing_collection_under_slash_4030'
        local_dir = os.path.join(self.testing_tmp_dir, base_name)

        try:
            ##################################
            # Setup
            ########
            dir1 = 'dir1'
            dir1path = os.path.join(local_dir, dir1)
            subdir1 = 'subdir1'
            subdir1path = os.path.join(dir1path, subdir1)

            target1 = '/'

            lib.make_dir_p(local_dir)
            lib.create_directory_of_small_files(dir1path,2)     # Two files in this one
            lib.create_directory_of_small_files(subdir1path,4)  # Four files in this one

            self.user0.run_icommand('icd {self.user0.session_collection}'.format(**locals()))

            # We put a collection into irods so that we can run icp.
            self.user0.assert_icommand('iput -r {dir1path}'.format(**locals()), "STDOUT_SINGLELINE", ustrings.recurse_ok_string())

            ##################################
            # Grouped tests (should) produce the same behavior and results:
            ########
            test_cases = [
                            'iput -r {dir1path} {target1}',
                            'irsync -r {dir1path} i:{target1}',
                            'icp -r {dir1} {target1}'
                         ]

            for cmdstring in test_cases:

                cmd = cmdstring.format(**locals())
                stdout,_,_ = self.user0.run_icommand(cmd)

                estr = 'SYS_INVALID_INPUT_PARAM]  errno [] -- message [a valid zone name does not appear at the root of the object path'
                self.assertIn(estr, stdout, '{cmd}: Expected stdout: "...{estr}...", got: "{stdout}"'.format(**locals()))

        finally:
            self.user0.run_icommand('irm -rf {dir1}'.format(**locals()))
            shutil.rmtree(os.path.abspath(dir1path), ignore_errors=True)

