import os
import subprocess
import sys
import tempfile
import unittest

from datetime import datetime, timedelta

from . import session
from .. import test
from .. import lib
from .. import paths
from ..configuration import IrodsConfig
from ..controller import IrodsController
from ..core_file import temporary_core_file

class Test_Misc(session.make_sessions_mixin([('otherrods', 'rods')], []), unittest.TestCase):

    plugin_name = IrodsConfig().default_rule_engine_plugin

    def setUp(self):
        super(Test_Misc, self).setUp()
        self.admin = self.admin_sessions[0]

    def tearDown(self):
        super(Test_Misc, self).tearDown()

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_invalid_client_irodsProt_handled_cleanly__issue_4130(self):
        env = os.environ.copy()
        env['irodsProt'] = '2'
        out, err, ec = lib.execute_command_permissive(['ils'], env=env)
        self.assertTrue('Invalid protocol value.' in err)

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', "only run for native rule language")
    def test_acpreconnect_has_client_addr__5985(self):
        try:
            with temporary_core_file() as core:
                data_object_path = os.path.join(
                    self.admin.session_collection, 'importantData')
                get_client_addr_rule = """
                    acPreConnect(*OUT) {{
                        *OUT = "CS_NEG_DONT_CARE";
                        msi_touch('{{"logical_path": "{path}"}}');
                        msiModAVUMetadata("-d", "{path}", "set", "clientAddr", $clientAddr, "ip address");
                    }}
                """.format(path=data_object_path)

                core.add_rule(get_client_addr_rule)
                IrodsController().reload_configuration()

                self.admin.assert_icommand(
                    'ils', 'STDOUT_SINGLELINE', os.path.basename(data_object_path))
                out, err, ec = self.admin.run_icommand(
                    ['imeta', 'ls', '-d', data_object_path, 'clientAddr'])

                self.assertGreater(len(out), 0)
                self.assertRegex(out, r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
                self.assertEqual(len(err), 0)
                self.assertEqual(ec, 0)

        finally:
            IrodsController().reload_configuration()

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_disallow_registration_of_path_with_missing_data_object_name__issue_4494(self):
        config = IrodsConfig()
        core_re_path = os.path.join(config.core_re_directory, 'core.re')

        try:
            with lib.file_backed_up(core_re_path):
                with open(core_re_path, 'a') as core_re:
                    core_re.write('''
                        test_registration_issue_4494 {{ 
                            *lpath = '{0}';
                            *ppath = '';
                            msiPhyPathReg(*lpath, 'null', *ppath, 'null', *status);
                        }}
                    '''.format(self.admin.session_collection + '/'))
                IrodsController(config).reload_configuration()

                rep = 'irods_rule_engine_plugin-irods_rule_language-instance'
                self.admin.assert_icommand(['irule', '-r', rep, 'test_registration_issue_4494', 'null', 'ruleExecOut'],
                                           'STDERR', ['-317000 USER_INPUT_PATH_ERR'])

        finally:
            IrodsController(config).reload_configuration()

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_disallow_creation_of_collections_with_path_navigation_elements_as_the_name__issue_4750(self):
        config = IrodsConfig()
        core_re_path = os.path.join(config.core_re_directory, 'core.re')

        try:
            with lib.file_backed_up(core_re_path):
                with open(core_re_path, 'a') as core_re:
                    core_re.write('''
                        test_dot_issue_4750 {{ 
                            *path = '{0}';
                            *recursive = 0;
                            msiCollCreate(*path, *recursive, *status);
                        }}

                        test_dot_dot_issue_4750 {{ 
                            *path = '{1}';
                            *recursive = 0;
                            msiCollCreate(*path, *recursive, *status);
                        }}

                        test_slash_slash_issue_4750 {{ 
                            *path = '{2}';
                            *recursive = 0;
                            msiCollCreate(*path, *recursive, *status);
                        }}
                    '''.format(self.admin.session_collection + '/.',
                               self.admin.session_collection + '/..',
                               self.admin.session_collection + '//'))
                IrodsController(config).reload_configuration()

                rep = 'irods_rule_engine_plugin-irods_rule_language-instance'

                for rule in ['test_dot_issue_4750', 'test_dot_dot_issue_4750']:
                    self.admin.assert_icommand(['irule', '-r', rep, rule, 'null', 'ruleExecOut'], 'STDERR', ['-317000 USER_INPUT_PATH_ERR'])

                self.admin.assert_icommand(['irule', '-r', rep, 'test_slash_slash_issue_4750', 'null', 'ruleExecOut'],
                                           'STDERR', ['-809000 CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME'])

        finally:
            IrodsController(config).reload_configuration()

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_catalog_reflects_truncation_on_open__issues_4483_4628(self):
        config = IrodsConfig()
        core_re_path = os.path.join(config.core_re_directory, 'core.re')

        try:
            with lib.file_backed_up(core_re_path):
                filename = os.path.join(self.admin.local_session_dir, 'truncated_file')
                lib.make_file(filename, 1024, 'arbitrary')
                self.admin.assert_icommand(['iput', filename])

                with open(core_re_path, 'a') as core_re:
                    core_re.write('''
                        test_truncate_on_open_4483_4628 {{ 
                            *path = '{0}';
                            *ec = 0;

                            msiDataObjOpen('objPath=*path++++openFlags=O_WRONLYO_TRUNC', *fd);

                            msiSplitPath(*path, *parent_path, *data_object);
                            foreach (*row in select DATA_SIZE where COLL_NAME = *parent_path and DATA_NAME = *data_object) {{
                                if (*row.DATA_SIZE != '0') {{
                                    *ec = -1;
                                }}
                            }}

                            msiDataObjClose(*fd, *status);

                            *ec;
                        }}
                    '''.format(os.path.join(self.admin.session_collection, os.path.basename(filename))))
                IrodsController(config).reload_configuration()

                rep = 'irods_rule_engine_plugin-irods_rule_language-instance'
                self.admin.assert_icommand(['irule', '-r', rep, 'test_truncate_on_open_4483_4628', 'null', 'ruleExecOut'])

        finally:
            IrodsController(config).reload_configuration()

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_return_error_on_incompatible_open_flags__issue_4782(self):
        rep = 'irods_rule_engine_plugin-irods_rule_language-instance'
        rule = "msiDataObjOpen('objPath=++++openFlags=O_RDONLYO_TRUNC', *fd)"
        self.admin.assert_icommand(['irule', '-r', rep, rule, 'null', 'ruleExecOut'], 'STDERR', ['-404000 USER_INCOMPATIBLE_OPEN_FLAGS'])

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_trailing_slashes_are_removed_when_creating_collections__issue_3892(self):
        collection = os.path.join(self.admin.session_collection, 'col_3892.d')
        self.admin.assert_icommand(['imkdir', collection])

        rep = 'irods_rule_engine_plugin-irods_rule_language-instance'
        rule = 'msiCollCreate("{0}", 0, *ignored)'.format(collection + '/')
        self.admin.assert_icommand(['irule', '-r', rep, rule, 'null', 'ruleExecOut'], 'STDERR', ['-809000 CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME'])

    @unittest.skipUnless(plugin_name == 'irods_rule_engine_plugin-irods_rule_language', 'only run for native rule language')
    def test_trailing_slashes_generate_an_error_when_opening_data_objects__issue_3892(self):
        data_object = os.path.join(self.admin.session_collection, 'dobj_3892')

        rep = 'irods_rule_engine_plugin-irods_rule_language-instance'
        rule = 'msiDataObjOpen("objPath={0}++++openFlags=O_WRONLYO_TRUNC", *fd)'.format(data_object + '/')
        self.admin.assert_icommand(['irule', '-r', rep, rule, 'null', 'ruleExecOut'], 'STDERR', ['-317000 USER_INPUT_PATH_ERR'])

        rule = 'msiDataObjCreate("{0}", "", *out)'.format(data_object + '/')
        self.admin.assert_icommand(['irule', '-r', rep, rule, 'null', 'ruleExecOut'], 'STDERR', ['-317000 USER_INPUT_PATH_ERR'])

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python' or test.settings.RUN_IN_TOPOLOGY, "Skip for Topology Testing")
    def test_return_error_on_resolution_of_empty_hostname__issue_5085(self):
        resource = 'issue_5085_resc'

        try:
            start = datetime.now()
            self.admin.assert_icommand(['iadmin', 'mkresc', resource, 'replication', ':'], 'STDOUT', ["'' is not a valid DNS entry"])
            self.assertLess(datetime.now() - start, timedelta(seconds=5))
        finally:
            self.admin.assert_icommand(['iadmin', 'rmresc', resource])

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', "Requires the Native Rule Engine Plugin.")
    def test_server_respawns_processes__issue_4977(self):
        import psutil
        import time
        from collections import defaultdict

        # Restart the server to make sure everything is in an expected state.
        IrodsController().restart(test_mode=True)

        main_server = None
        sescoln = self.admin.session_collection
        object_name = sescoln+"/hello"

        try:
            # Find the main server process
            for proc in psutil.process_iter():
                # It won't have any parents.
                if proc.name() == 'irodsServer' and proc.parent().name() != 'irodsServer':
                    main_server = proc
                    break

            # It's possible that the server was never found, which would be a problem.
            self.assertIsNotNone(main_server)

            # Kill the agent factory and the delay server
            for child in main_server.children(recursive=True):
                child.kill()

            # If the API is up after this it seems it should be entirely working.
            # run_icommand returns (stdout, stderr, returncode), so try until itouch returns 0.
            lib.delayAssert(lambda: self.admin.run_icommand(['itouch', object_name])[2] == 0)

            def process_has_at_least_two_child_processes_with_expected_names(proc):
                children = proc.children()
                # debugging print
                print(children)
                for c in children:
                    # debugging print
                    print(f'child name [{c.name()}]')
                    if c.name() != 'irodsDelayServer' and c.name() != 'irodsAgent':
                        return False
                return len(children) >= 2

            # Make super-extra sure that both the delay server and the agent factory are up.
            # This check is necessary because it has been observed that the name of child
            # processes can be truncated and then later respawned with the correct name.
            lib.delayAssert(lambda:
                    process_has_at_least_two_child_processes_with_expected_names(main_server))

            # Double-check that there is exactly one delay server and exactly one agent factory
            # instance. As the agent factory process shares a name with the main server process
            # as well as iRODS agent processes, we check for the 'irodsServer' process name.
            def exactly_one_delay_server_and_agent_factory_exist():
                seen_process_names = defaultdict(int)
                for i in main_server.children():
                    seen_process_names[i.name()] += 1
                # debugging print
                print(seen_process_names)
                return 1 == seen_process_names['irodsDelayServer'] and 1 == seen_process_names['irodsAgent']

            lib.delayAssert(exactly_one_delay_server_and_agent_factory_exist)

            # Test the delay server
            attribute = "a1"
            value = "v1"
            self.admin.assert_icommand(['irule', '-r',
                                        "irods_rule_engine_plugin-irods_rule_language-instance",
                                        'delay("<INST_NAME>irods_rule_engine_plugin-irods_rule_language-instance</INST_NAME>") {{ msiModAVUMetadata("-d", "{}", "add", "{}", "{}", "u2") }}'.format(object_name, attribute, value),
                                        'null',
                                        'ruleExecOut'])

            # Wait for the delay server to process the rule
            lib.delayAssert(lambda: lib.metadata_attr_with_value_exists(self.admin, attribute, value))

            # #6117 - If the child count never drops back down to 2 (that is, only the delay
            # server and the agent factory are child processes of the main server process), then
            # that means the agents are leaking.
            lib.delayAssert(lambda: len(main_server.children(recursive=True)) < 3)

        finally:
            self.admin.run_icommand(['irm', "-f", 'hello'])
            # Restart the server to make sure everything is in an expected state.
            IrodsController().restart(test_mode=True)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    def test_server_correctly_cleans_up_proc_files__issue_6231(self):
        # Generate some proc files.
        for i in range(10):
            self.admin.assert_icommand(['ils'], 'STDOUT', [self.admin.session_collection])

        # Show that the proc directory will eventually become empty.
        lib.delayAssert(lambda: len(os.listdir(paths.proc_directory())) == 0)

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', "only run for native rule language")
    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    def test_client_side_and_server_side_filesystem_library_interfaces_can_be_used_in_same_translation_unit__issue_6782(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_issue_6782', 'null', 'ruleExecOut'])

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', "only run for native rule language")
    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    def test_client_side_and_server_side_dstream_library_interfaces_can_be_used_in_same_translation_unit__issue_6829(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_issue_6829', 'null', 'ruleExecOut'])

    @unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', "only run for native rule language")
    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    def test_scoped_client_identity_updates_zone_of_RsComm__issue_6268(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_scoped_client_identity', 'null', 'ruleExecOut'])

    @unittest.skipUnless(plugin_name == 'irods_rule_engine_plugin-irods_rule_language', "Not implemented for other REPs.")
    def test_scoped_permission__issue_7032(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_scoped_permission', 'null', 'ruleExecOut'])

    @unittest.skipUnless(plugin_name == 'irods_rule_engine_plugin-irods_rule_language', "Not implemented for other REPs.")
    def test_msp_functions(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_msp_functions', 'null', 'ruleExecOut'])

    @unittest.skipUnless(plugin_name == 'irods_rule_engine_plugin-irods_rule_language', "Not implemented for other REPs.")
    def test_user_administration__issue_7208(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_user_administration', 'null', 'ruleExecOut'])

    @unittest.skipIf(test.settings.USE_SSL, 'iinit does not correctly create irods_environment.json with SSL enabled.')
    def test_iinit_does_not_crash_from_long_home_directory__issue_5411(self):
        with tempfile.TemporaryDirectory() as temp_dir_name:
            # Create new home directory for test
            temp_home = os.path.join(temp_dir_name, 'crazy', 'long', 'temp', 'home', 'directory',
                                     'like', 'this', 'is', 'longer', 'than', 'the', 'solos', 'in', 'chameleon')
            os.makedirs(temp_home)

            # Setup environment
            temp_env = os.environ.copy()
            temp_env['HOME'] = temp_home

            # Setup input for execution
            user_input = os.linesep.join(
                ['localhost', '1247', 'rods', 'tempZone', 'rods']) + os.linesep
            command = 'iinit'

            # Execute iinit
            # Avoid using *_icommand(...), as they set the auth file location to a separate, shorter directory!
            stdout, stderr, rc = lib.execute_command_permissive(command, input=user_input, env=temp_env)
            lib.log_command_result(command, stdout, stderr, rc)

            # Ensure program terminated gracefully
            self.assertEqual(rc, 0)

            # Check all input prompted
            self.assertIn('Enter the host name (DNS) of the server to connect to', stdout)
            self.assertIn('Enter the port number', stdout)
            self.assertIn('Enter your iRODS user name', stdout)
            self.assertIn('Enter your iRODS zone', stdout)
            self.assertIn('Enter your current iRODS password', stdout)

            # Check expected error exists
            error_string = ' ERROR: environment_properties::capture: missing environment file. should be at [{}/.irods/irods_environment.json]\n'.format(
                temp_home)
            self.assertEqual(stderr, error_string)


    def test_tcp_keepalive_time__issue_2533_3824(self):
        # This test sets the iRODS TCP keepalive time to various values. Due to the nature of TCP socket timeouts, this
        # does not test the behavior of the TCP keepalive options on the sockets. It mainly demonstrates the range of
        # values allowed by the system.
        self.env = os.environ.copy()

        # Test with tcp_keepalive_time unset.
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_time set to 1. This is the smallest valid value and should not affect behavior.
        self.env['IRODS_TCP_KEEPALIVE_TIME_IN_SECONDS'] = str(1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_time set to 0. This value is invalid, but is detected by the socket-creating function
        # and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_TIME_IN_SECONDS'] = str(0)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_time set to 0. This value is invalid, but is detected by the socket-creating function
        # and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_TIME_IN_SECONDS'] = str(-1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_time set to INT32_MAX. This value is invalid and is not detected by the
        # socket-creating function, so it attempts to set the socket option and fails because the value is invalid.
        # Check for SOCKET_ERROR (-179000) with an errno of 22 (Invalid argument).
        self.env['IRODS_TCP_KEEPALIVE_TIME_IN_SECONDS'] = str(2147483647)
        self.admin.assert_icommand('ils', 'STDERR', '-179022 SOCKET_ERROR, Invalid argument', env=self.env)


    def test_tcp_keepalive_intvl__issue_2533_3824(self):
        # This test sets the iRODS TCP keepalive interval to various values. Due to the nature of TCP socket timeouts,
        # this does not test the behavior of the TCP keepalive options on the sockets. It mainly demonstrates the range
        # of values allowed by the system.
        self.env = os.environ.copy()

        # Test with tcp_keepalive_intvl unset.
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_intvl set to 1. This is the smallest valid value and should not affect behavior.
        self.env['IRODS_TCP_KEEPALIVE_INTVL_IN_SECONDS'] = str(1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_intvl set to 0. This value is invalid, but is detected by the socket-creating function
        # and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_INTVL_IN_SECONDS'] = str(0)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_intvl set to 0. This value is invalid, but is detected by the socket-creating function
        # and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_INTVL_IN_SECONDS'] = str(-1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_intvl set to INT32_MAX. This value is invalid and is not detected by the
        # socket-creating function, so it attempts to set the socket option and fails because the value is invalid.
        # Check for SOCKET_ERROR (-179000) with an errno of 22 (Invalid argument).
        self.env['IRODS_TCP_KEEPALIVE_INTVL_IN_SECONDS'] = str(2147483647)
        self.admin.assert_icommand('ils', 'STDERR', '-179022 SOCKET_ERROR, Invalid argument', env=self.env)


    def test_tcp_keepalive_probes__issue_2533_3824(self):
        # This test sets the iRODS TCP keepalive probes to various values. Due to the nature of TCP socket timeouts,
        # this does not test the behavior of the TCP keepalive options on the sockets. It mainly demonstrates the range
        # of values allowed by the system.
        self.env = os.environ.copy()

        # Test with tcp_keepalive_probes unset.
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_probes set to 1. This is the smallest valid value and should not affect behavior.
        self.env['IRODS_TCP_KEEPALIVE_PROBES'] = str(1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_probes set to 0. This value is invalid, but is detected by the socket-creating
        # function and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_PROBES'] = str(0)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_probes set to 0. This value is invalid, but is detected by the socket-creating
        # function and ignored, effectively leaving it unset.
        self.env['IRODS_TCP_KEEPALIVE_PROBES'] = str(-1)
        self.admin.assert_icommand('ils', 'STDOUT', self.admin.session_collection, env=self.env)

        # Test with tcp_keepalive_probes set to INT32_MAX. This value is invalid and is not detected by the
        # socket-creating function, so it attempts to set the socket option and fails because the value is invalid.
        # Check for SOCKET_ERROR (-179000) with an errno of 22 (Invalid argument).
        self.env['IRODS_TCP_KEEPALIVE_PROBES'] = str(2147483647)
        self.admin.assert_icommand('ils', 'STDERR', '-179022 SOCKET_ERROR, Invalid argument', env=self.env)

    @unittest.skipUnless(plugin_name == 'irods_rule_engine_plugin-irods_rule_language', "Not implemented for other REPs.")
    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, "skip for topology testing")
    def test_server_side_delay_rule_locking_API__issue_8023(self):
        self.admin.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', 'msi_test_delay_rule_locking_api', 'null', 'ruleExecOut'])

    def test_logical_path_including_the_AND_keyword_SPACES_and_a_SINGLE_QUOTATION_MARK_does_not_result_in_an_error__issue_8033(self):
        coll_name = 'colA and colB'
        self.admin.assert_icommand(['imkdir', coll_name])
        self.admin.assert_icommand(['ils', coll_name], 'STDOUT', [os.path.join(self.admin.session_collection, coll_name)])

        data_object = f"{coll_name}/myfile'"
        self.admin.assert_icommand(['itouch', data_object])
        self.admin.assert_icommand(['ils', data_object], 'STDOUT', [os.path.join(self.admin.session_collection, data_object)])

        filename = "myfile' name and id"
        try:
            lib.make_file(filename, 1)
            self.admin.assert_icommand(['iput', filename])
            self.admin.assert_icommand(['ils', filename], 'STDOUT', [os.path.join(self.admin.session_collection, filename)])

        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    @unittest.skipIf(test.settings.RUN_IN_TOPOLOGY, 'Only requires a single server')
    def test_configuration_validation_reports_fqdn_size_violations__issue_8287(self):
        # See https://web.archive.org/web/20190518124533/https://devblogs.microsoft.com/oldnewthing/?p=7873
        # to understand why the "host" property limits the length to 253 characters.

        config = IrodsConfig()

        with lib.file_backed_up(config.server_config_path):
            with self.subTest('"host" property is an empty string'):
                config.server_config['host'] = ''
                lib.update_json_file_from_dict(config.server_config_path, config.server_config)
                res = subprocess.run(['irodsServer', '-c'], capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn('"valid": false', res.stderr)
                self.assertIn('"instanceLocation": "/host"', res.stderr)
                self.assertIn('"error": "Number of characters must be at least 1"', res.stderr)

            with self.subTest('"host" property has size matching limit (253 characters)'):
                config.server_config['host'] = 'a' * 253
                lib.update_json_file_from_dict(config.server_config_path, config.server_config)
                res = subprocess.run(['irodsServer', '-c'], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0)
                self.assertEqual(len(res.stderr), 0)

            with self.subTest('"host" property has size exceeding limit (253 characters)'):
                config.server_config['host'] = 'a' * 254
                lib.update_json_file_from_dict(config.server_config_path, config.server_config)
                res = subprocess.run(['irodsServer', '-c'], capture_output=True, text=True)
                self.assertNotEqual(res.returncode, 0)
                self.assertIn('"valid": false', res.stderr)
                self.assertIn('"instanceLocation": "/host"', res.stderr)
                self.assertIn('"error": "Number of characters must be at most 253"', res.stderr)

    @unittest.skipIf(test.settings.TOPOLOGY_FROM_RESOURCE_SERVER, 'Test must be run from the Catalog Service Provider')
    def test_server_returns_SYS_EXCEED_CONNECT_CNT_when_redirect_loop_to_self_is_detected__issue_8529(self):
        # This test requires that the Catalog Service Provider be identifiable by two names. This
        # requirement is satisfied by the iRODS Testing Environment because setup_irods.py produces a
        # server_config.json which initializes the "host" property to the container id while also allowing
        # the same container to be identified (internally) as "irods-catalog-provider".

        # Force the test to fail if the provider cannot be reached by its alternative name. This test is
        # designed to align with the environment seen in the iRODS Testing Environment.
        hostname_alias = 'irods-catalog-provider'
        try:
            admin = session.make_session_for_existing_admin(hostname_alias)
            admin.__exit__()
        except AssertionError:
            raise EnvironmentError('Catalog Service Provider must be reachable by hostname [irods-catalog-provider]')

        # Force the test to fail if the provider cannot be identified by at least two different names.
        if IrodsConfig().server_config['host'] == hostname_alias:
            raise EnvironmentError('[host] property in server_config.json cannot match [irods-catalog-provider]')

        resc_name = 'issue_8529_resc'
        local_file = os.path.join(self.admin.local_session_dir, 'issue_8529_file.txt')

        try:
            lib.create_ufs_resource(self.admin, resc_name, hostname=hostname_alias)
            lib.create_ascii_printable_file(local_file, 1)
            self.admin.assert_icommand(['iput', '-R', resc_name, local_file], 'STDERR', ['-9000 SYS_EXCEED_CONNECT_CNT'])

        finally:
            self.admin.run_icommand(['irm', '-f', os.path.basename(local_file)])
            self.admin.run_icommand(['iadmin', 'rmresc', resc_name])
