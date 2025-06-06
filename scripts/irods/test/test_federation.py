from __future__ import print_function

from textwrap import dedent
import os
import shutil
import socket
import tempfile
import time
import unittest

from . import session
from . import settings
from .. import lib
from .. import paths
from .. import test
from ..configuration import IrodsConfig
from ..controller import IrodsController
from ..core_file import temporary_core_file

SessionsMixin = session.make_sessions_mixin(
	test.settings.FEDERATION.RODSADMIN_NAME_PASSWORD_LIST, test.settings.FEDERATION.RODSUSER_NAME_PASSWORD_LIST)

# This test script expects tempZone to contain the following users:
#
#   - rods#tempZone
#   - zonehopper#tempZone
#   - zonehopper#otherZone
#
# otherZone must contain the following user:
#
#   - rods#otherZone
#
# The test script must be launched from a server in otherZone. That means tempZone
# is identified as the remote federated zone.

class Test_ICommands(SessionsMixin, unittest.TestCase):

	def setUp(self):
		super(Test_ICommands, self).setUp()

		# make local test directory
		self.local_test_dir_path = '/tmp/federation_test_stuff'
		os.mkdir(self.local_test_dir_path)

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val
		self.config['local_zone'] = self.user_sessions[0].zone_name
		if test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 0, 0):
			test.settings.FEDERATION.REMOTE_VAULT = '/home/irods/irods-legacy/iRODS/Vault'

	def tearDown(self):
		shutil.rmtree(self.local_test_dir_path, ignore_errors=True)
		super(Test_ICommands, self).tearDown()

	def test_iquest__3466(self):
		if 'otherZone' == test.settings.FEDERATION.REMOTE_ZONE:
			self.admin_sessions[0].assert_icommand('iquest -z otherZone --sql bug_3466_query', 'STDOUT_SINGLELINE', 'bug_3466_query')

	def test_ils_l(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		with tempfile.NamedTemporaryFile() as f:
			filename = os.path.basename(f.name)
			filesize = test.settings.FEDERATION.TEST_FILE_SIZE
			lib.make_file(f.name, filesize, 'arbitrary')
			remote_home_collection = test_session.remote_home_collection(
				test.settings.FEDERATION.REMOTE_ZONE)

			test_session.assert_icommand(
				['ils', '-L', remote_home_collection], 'STDOUT_SINGLELINE', remote_home_collection)
			test_session.assert_icommand(
				['iput', f.name, remote_home_collection])

			# list file info
			test_session.assert_icommand(
				['ils', '-L', '{0}/{1}'.format(remote_home_collection, filename)], 'STDOUT_SINGLELINE', filename)
			test_session.assert_icommand(
				['ils', '-L', '{0}/{1}'.format(remote_home_collection, filename)], 'STDOUT_SINGLELINE', str(filesize))
			test_session.assert_icommand(
				['ils', '-L', '{0}/{1}'.format(remote_home_collection, filename)], 'STDOUT_SINGLELINE', test.settings.FEDERATION.REMOTE_DEF_RESOURCE)
			test_session.assert_icommand(
				['ils', '-L', '{0}/{1}'.format(remote_home_collection, filename)], 'STDOUT_SINGLELINE', test.settings.FEDERATION.REMOTE_VAULT)

			# cleanup
			test_session.assert_icommand(
				['irm', '-f', '{0}/{1}'.format(remote_home_collection, filename)])

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 0), 'Fixed in 4.2.0')
	def test_ils_A(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		with tempfile.NamedTemporaryFile() as f:
			filename = os.path.basename(f.name)
			filesize = test.settings.FEDERATION.TEST_FILE_SIZE
			lib.make_file(f.name, filesize, 'arbitrary')
			remote_home_collection = test_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
			username = test_session.username
			local_zone = test_session.zone_name

			# put file in remote collection
			test_session.assert_icommand(
				['iput', f.name, remote_home_collection])

			# icd to remote collection
			test_session.assert_icommand(['icd', remote_home_collection])

			# list object's ACLs
			test_session.assert_icommand(
				['ils', '-A', filename], 'STDOUT_SINGLELINE', "ACL - {username}#{local_zone}:own".format(**locals()))

			# cleanup
			test_session.assert_icommand(
				['irm', '-f', '{0}/{1}'.format(remote_home_collection, filename)])


	@unittest.skipUnless(test.settings.USE_SSL, 'This test uses SSL and so it is required in order to run.')
	def test_ils_with_misconfigured_ssl_catches_exceptions__issue_6365(self):
		test_session = self.user_sessions[0]
		remote_home_collection = test_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
		test_session.assert_icommand(['ils', remote_home_collection], 'STDOUT_SINGLELINE', remote_home_collection)
		try:
			with temporary_core_file() as core:
				# Disable SSL communications in the local server. This should break communications with the remote zone,
				# which is supposed to be configured for SSL communications.
				core.add_rule('acPreConnect(*OUT) { *OUT = "CS_NEG_REFUSE"; }')
				IrodsController().reload_configuration()
		
				# Disable SSL communications in the service account client environment so that it can communicate with
				# the local server, which has just disabled SSL communications.
				env_update = {'irods_client_server_policy': 'CS_NEG_REFUSE'}
				service_account_env_file = os.path.join(paths.irods_directory(), '.irods', "irods_environment.json")
				with lib.file_backed_up(service_account_env_file):
					lib.update_json_file_from_dict(service_account_env_file, env_update)
		
					# Disable SSL communications in the test session client environment so that it can communicate with
					# the local server, which has just disabled SSL communications.
					client_env_file = os.path.join(test_session.local_session_dir, "irods_environment.json")
					with lib.file_backed_up(client_env_file):
						lib.update_json_file_from_dict(client_env_file, env_update)
		
						# Make sure communications with the local zone are in working order...
						_, pwd, _ = test_session.assert_icommand(['ipwd'], 'STDOUT', test_session.zone_name)
						test_session.assert_icommand(['ils'], 'STDOUT_SINGLELINE', pwd.strip())
		
						# ils in the remote zone should fail due to the misconfigured SSL settings, but not explode.
						out, err, rc = test_session.run_icommand(['ils', remote_home_collection])
						self.assertNotEqual(0, rc)
						self.assertEqual(0, len(out))
						self.assertIn('iRODS filesystem error occurred', err)
						self.assertNotIn('terminating with uncaught exception', err)
		
		finally:
			IrodsController().reload_configuration()

	def test_ils_subcolls(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# test specific parameters
		parameters = self.config.copy()
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)
		parameters['subcoll0'] = "{remote_home_collection}/subcoll0".format(
			**parameters)
		parameters['subcoll1'] = "{remote_home_collection}/subcoll1".format(
			**parameters)

		# make subcollections in remote coll
		test_session.assert_icommand("imkdir {subcoll0}".format(**parameters))
		test_session.assert_icommand("imkdir {subcoll1}".format(**parameters))

		# list remote home collection and look for subcollections
		test_session.assert_icommand(
			"ils {remote_home_collection}".format(**parameters), 'STDOUT_MULTILINE', [parameters['subcoll0'], parameters['subcoll1']])

		# cleanup
		test_session.assert_icommand("irm -r {subcoll0}".format(**parameters))
		test_session.assert_icommand("irm -r {subcoll1}".format(**parameters))

	def test_iput(self):
		self.basic_iput_test(self.config['test_file_size'])

	def test_iput_large_file(self):
		self.basic_iput_test(self.config['large_file_size'])

	def basic_iput_test(self, filesize):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'iput_test_file'
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		if filesize >= self.config['large_file_size']:
			# put file in remote collection, ask for 4 threads
			test_session.assert_icommand(
				"iput -v -N 4 {filepath} {remote_home_collection}/".format(**parameters), 'STDOUT_SINGLELINE', '4 thr')
		else:
			# put file in remote collection
			test_session.assert_icommand(
				"iput {filepath} {remote_home_collection}/".format(**parameters))

		# file should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', filename)
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', str(filesize))

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))
		os.remove(filepath)

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 1, 9), 'Fixed in 4.1.9')
	def test_slow_ils_over_federation__ticket_3215(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'iput_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, 500, 30)

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in remote collection
		test_session.assert_icommand(
			"iput -r {dir_path} {remote_home_collection}/".format(**parameters))

		# time listing of collection
		t0 = time.time()
		test_session.assert_icommand(
			"ils -AL {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)
		t1 = time.time()

		diff = t1 - t0
		self.assertTrue(diff<20)

		# cleanup
		test_session.assert_icommand(
			"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
		shutil.rmtree(dir_path)

	def test_iput_r(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'iput_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, self.config['test_file_count'], self.config['test_file_size'])

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in remote collection
		test_session.assert_icommand(
			"iput -r {dir_path} {remote_home_collection}/".format(**parameters))

		# new collection should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

		# files should be there
		rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
		self.assertTrue(set(local_files) == rods_files)

		# cleanup
		test_session.assert_icommand(
			"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
		shutil.rmtree(dir_path)

	def test_iget(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'iget_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# checksum local file
		orig_md5 = lib.file_digest(filepath, 'md5')

		# put file in remote collection
		test_session.assert_icommand(
			"iput {filepath} {remote_home_collection}/".format(**parameters))

		# remove local file
		os.remove(filepath)

		# get file back
		test_session.assert_icommand(
			"iget {remote_home_collection}/{filename} {filepath}".format(**parameters))

		# compare checksums
		new_md5 = lib.file_digest(filepath, 'md5')
		self.assertEqual(orig_md5, new_md5)

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))
		os.remove(filepath)

	def test_iget_large_file(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'iget_test_file'
		filesize = self.config['large_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# checksum local file
		orig_md5 = lib.file_digest(filepath, 'md5')

		# put file in remote collection
		test_session.assert_icommand(
			"iput {filepath} {remote_home_collection}/".format(**parameters))

		# remove local file
		os.remove(filepath)

		# for the next transfer we expect the number of threads
		# to be capped at max_threads or max_threads+1,
		# e.g: we will look for '4 thr' or '5 thr' in stdout
		parameters['max_threads_plus_one'] = parameters['max_threads'] + 1
		expected_output_regex = '[{max_threads}|{max_threads_plus_one}] thr'.format(
			**parameters)

		# get file back, ask for too many threads (should be capped)
		test_session.assert_icommand(
			"iget -v -N 600 {remote_home_collection}/{filename} {filepath}".format(**parameters), 'STDOUT_SINGLELINE', expected_output_regex, use_regex=True)

		# compare checksums
		new_md5 = lib.file_digest(filepath, 'md5')
		self.assertEqual(orig_md5, new_md5)

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))
		os.remove(filepath)

	def test_iget_r(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'iget_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, self.config['test_file_count'], self.config['test_file_size'])

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in remote collection
		test_session.assert_icommand(
			"iput -r {dir_path} {remote_home_collection}/".format(**parameters))

		# remove local test dir
		shutil.rmtree(dir_path)

		# get collection back
		test_session.assert_icommand(
			"iget -r {remote_home_collection}/{dir_name} {dir_path}".format(**parameters))

		# compare list of files
		received_files = os.listdir(dir_path)
		self.assertTrue(set(local_files) == set(received_files))

		# cleanup
		test_session.assert_icommand(
			"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
		shutil.rmtree(dir_path)

	def test_irm_f(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'irm_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put file in remote collection
		test_session.assert_icommand(
			"iput {filepath} {remote_home_collection}/".format(**parameters))

		# file should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', filename)

		# delete remote file
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))

		# file should be gone
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDERR_SINGLELINE', 'does not exist')

		# cleanup
		os.remove(filepath)

	def test_irm_rf(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'irm_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, self.config['test_file_count'], self.config['test_file_size'])

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in remote collection
		test_session.assert_icommand(
			"iput -r {dir_path} {remote_home_collection}/".format(**parameters))

		# new collection should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

		# files should be there
		rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
		self.assertTrue(set(local_files) == rods_files)

		# remove remote coll
		test_session.assert_icommand(
			"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))

		# coll should be gone
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDERR_SINGLELINE', 'does not exist')

		# cleanup
		shutil.rmtree(dir_path)

	def test_icp(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'icp_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['local_home_collection'] = test_session.home_collection
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		try:
			lib.make_file(filepath, filesize)

			# checksum local file
			orig_md5 = lib.file_digest(filepath, 'md5')

			# put file in local collection
			test_session.assert_icommand(
				"iput {filepath} {local_home_collection}/".format(**parameters))

			# remove local file
			os.remove(filepath)

			# copy file to remote home collection
			test_session.assert_icommand(
				"icp {local_home_collection}/{filename} {remote_home_collection}/".format(**parameters))

			# file should show up in remote zone
			test_session.assert_icommand(
				"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', filename)
			test_session.assert_icommand(
				"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', str(filesize))

			# get file back from remote zone
			test_session.assert_icommand(
				"iget {remote_home_collection}/{filename} {filepath}".format(**parameters))

			# compare checksums
			new_md5 = lib.file_digest(filepath, 'md5')
			self.assertEqual(orig_md5, new_md5)

		finally:
			print(test_session.run_icommand("ils -L {remote_home_collection}")[0])

			# cleanup
			test_session.run_icommand(
				"irm -f {local_home_collection}/{filename}".format(**parameters))
			test_session.run_icommand(
				"irm -f {remote_home_collection}/{filename}".format(**parameters))
			os.remove(filepath)

	def test_icp_large(self):
		# test settings
		remote_zone = self.config['remote_zone']
		test_session = self.user_sessions[0]
		local_zone = test_session.zone_name
		user_name = test_session.username
		local_home_collection = test_session.home_collection
		remote_home_collection = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**locals())

		# make test file
		filename = 'icp_test_file'
		filesize = self.config['large_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# checksum local file
		orig_md5 = lib.file_digest(filepath, 'md5')

		# put file in local collection
		test_session.assert_icommand(
			"iput {filepath} {local_home_collection}/".format(**locals()))

		# remove local file
		os.remove(filepath)

		# copy file to remote home collection
		test_session.assert_icommand(
			"icp {local_home_collection}/{filename} {remote_home_collection}/".format(**locals()))

		# file should show up in remote zone
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**locals()), 'STDOUT_SINGLELINE', filename)
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**locals()), 'STDOUT_SINGLELINE', str(filesize))

		# get file back from remote zone
		test_session.assert_icommand(
			"iget {remote_home_collection}/{filename} {filepath}".format(**locals()))

		# compare checksums
		new_md5 = lib.file_digest(filepath, 'md5')
		self.assertEqual(orig_md5, new_md5)

		# cleanup
		test_session.assert_icommand(
			"irm -f {local_home_collection}/{filename}".format(**locals()))
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**locals()))
		os.remove(filepath)

	def test_icp_f_large(self):
		# test settings
		remote_zone = self.config['remote_zone']
		test_session = self.user_sessions[0]
		local_zone = test_session.zone_name
		user_name = test_session.username
		local_home_collection = test_session.home_collection
		remote_home_collection = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**locals())

		# make test file
		filename = 'icp_test_file'
		filesize = self.config['large_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# checksum local file
		orig_md5 = lib.file_digest(filepath, 'md5')

		# put file in local collection
		test_session.assert_icommand(
			"iput {filepath} {local_home_collection}/".format(**locals()))

		# remove local file
		os.remove(filepath)

		# copy file to remote home collection
		test_session.assert_icommand(
			"icp -f {local_home_collection}/{filename} {remote_home_collection}/".format(**locals()))

		# file should show up in remote zone
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**locals()), 'STDOUT_SINGLELINE', filename)
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**locals()), 'STDOUT_SINGLELINE', str(filesize))

		# get file back from remote zone
		test_session.assert_icommand(
			"iget {remote_home_collection}/{filename} {filepath}".format(**locals()))

		# compare checksums
		new_md5 = lib.file_digest(filepath, 'md5')
		self.assertEqual(orig_md5, new_md5)

		# cleanup
		test_session.assert_icommand(
			"irm -f {local_home_collection}/{filename}".format(**locals()))
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**locals()))
		os.remove(filepath)

	def test_icp_r(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'icp_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, self.config['test_file_count'], self.config['test_file_size'])

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['local_home_collection'] = test_session.home_collection
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in local collection
		test_session.assert_icommand(
			"iput -r {dir_path} {local_home_collection}/".format(**parameters))

		# remove local test dir
		shutil.rmtree(dir_path)

		# copy dir to remote home collection
		test_session.assert_icommand(
			"icp -r {local_home_collection}/{dir_name} {remote_home_collection}/{dir_name}".format(**parameters))

		# collection should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

		# files should be there
		rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
		self.assertTrue(set(local_files) == rods_files)

		# get collection back
		test_session.assert_icommand(
			"iget -r {remote_home_collection}/{dir_name} {dir_path}".format(**parameters))

		# compare list of files
		received_files = os.listdir(dir_path)
		self.assertTrue(set(local_files) == set(received_files))

		# cleanup
		test_session.assert_icommand(
			"irm -rf {local_home_collection}/{dir_name}".format(**parameters))
		test_session.assert_icommand(
			"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
		shutil.rmtree(dir_path)

	def test_imv(self):
		'''
		remote-remote imv test
		(SYS_CROSS_ZONE_MV_NOT_SUPPORTED)
		'''
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'imv_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['new_name'] = filename = '_new'
		parameters['user_name'] = test_session.username
		parameters['local_home_collection'] = test_session.home_collection
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put file in remote collection
		test_session.assert_icommand(
			"iput {filepath} {remote_home_collection}/".format(**parameters))

		# move (rename) remote file
		test_session.assert_icommand(
			"imv {remote_home_collection}/{filename} {remote_home_collection}/{new_name}".format(**parameters))

		# file should have been renamed
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDERR_SINGLELINE', 'does not exist')
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{new_name}".format(**parameters), 'STDOUT_SINGLELINE', filename)
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{new_name}".format(**parameters), 'STDOUT_SINGLELINE', str(filesize))

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{new_name}".format(**parameters))
		os.remove(filepath)

	def test_irsync_r_dir_to_coll(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# test specific parameters
		dir_name = 'irsync_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)

		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		try:
			# make test dir
			local_files = lib.make_large_local_tmp_dir(
				dir_path, self.config['test_file_count'], self.config['test_file_size'])

			# sync dir with remote collection
			test_session.assert_icommand(
				"irsync -r {dir_path} i:{remote_home_collection}/{dir_name}".format(**parameters))

			# new collection should be there
			test_session.assert_icommand(
				"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

			# files should be there
			rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
			self.assertTrue(set(local_files) == rods_files)

		finally:
			# cleanup
			test_session.run_icommand(
				"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
			shutil.rmtree(dir_path)

	def test_irsync_r_coll_to_coll(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# test specific parameters
		dir_name = 'irsync_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)

		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['local_home_collection'] = test_session.home_collection
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		try:
			# make test dir
			local_files = lib.make_large_local_tmp_dir(
				dir_path, self.config['test_file_count'], self.config['test_file_size'])

			# put dir in local collection
			test_session.assert_icommand(
				"iput -r {dir_path} {local_home_collection}/".format(**parameters))

			# remove local test dir
			shutil.rmtree(dir_path)

			# sync local collection with remote collection
			test_session.assert_icommand(
				"irsync -r i:{local_home_collection}/{dir_name} i:{remote_home_collection}/{dir_name}".format(**parameters))

			# collection should be there
			test_session.assert_icommand(
				"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

			# files should be there
			rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
			self.assertTrue(set(local_files) == rods_files)

			# get collection back
			test_session.assert_icommand(
				"iget -r {remote_home_collection}/{dir_name} {dir_path}".format(**parameters))

			# compare list of files
			received_files = os.listdir(dir_path)
			self.assertTrue(set(local_files) == set(received_files))

		finally:
			# cleanup
			test_session.run_icommand(
				"irm -rf {local_home_collection}/{dir_name}".format(**parameters))
			test_session.run_icommand(
				"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
			shutil.rmtree(dir_path)

	def test_irsync_r_coll_to_dir(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# test specific parameters
		dir_name = 'irsync_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)

		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		try:
			# make test dir
			local_files = lib.make_large_local_tmp_dir(
				dir_path, self.config['test_file_count'], self.config['test_file_size'])

			# sync dir with remote collection
			test_session.assert_icommand(
				"irsync -r {dir_path} i:{remote_home_collection}/{dir_name}".format(**parameters))

			# remove local test dir
			shutil.rmtree(dir_path)

			# sync remote collection back with local dir
			test_session.assert_icommand(
				"irsync -r i:{remote_home_collection}/{dir_name} {dir_path}".format(**parameters))

			# compare list of files
			received_files = os.listdir(dir_path)
			self.assertTrue(set(local_files) == set(received_files))

		finally:
			# cleanup
			test_session.run_icommand(
				"irm -rf {remote_home_collection}/{dir_name}".format(**parameters))
			shutil.rmtree(dir_path)

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 0, 0) or test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 0, 0), 'No resource hierarchies before iRODS 4')
	def test_irsync_passthru_3016(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# test specific parameters
		filename = 'irsync_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)

		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['local_home_collection'] = test_session.home_collection
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# extract resources from hierarchies
		(parameters['local_pt_resc'], parameters['local_leaf_resc']) = tuple(
			parameters['local_pt_resc_hier'].split(';'))
		parameters['remote_pt_resc'] = parameters[
			'remote_pt_resc_hier'].split(';')[0]

		parameters['hostname'] = test.settings.ICAT_HOSTNAME
		parameters['local_leaf_resc_path'] = '/tmp/{local_leaf_resc}'.format(
			**parameters)

		try:
			# make test file
			lib.make_file(filepath, filesize)

			# create local passthru hierarchy
			self.admin_sessions[0].run_icommand(
				"iadmin mkresc {local_pt_resc} passthru".format(**parameters))
			self.admin_sessions[0].run_icommand(
				"iadmin mkresc {local_leaf_resc} unixfilesystem {hostname}:{local_leaf_resc_path}".format(**parameters))
			self.admin_sessions[0].run_icommand(
				"iadmin addchildtoresc {local_pt_resc} {local_leaf_resc}".format(**parameters))

			# checksum local file
			orig_md5 = lib.file_digest(filepath, 'md5')

			# put file in local collection, using local passthru resource
			test_session.assert_icommand(
				"iput -R {local_pt_resc} {filepath} {local_home_collection}/".format(**parameters))

			# remove local file
			os.remove(filepath)

			# rsync file into remote coll, using remote passthru resource
			test_session.assert_icommand(
				"irsync -R {remote_pt_resc} i:{local_home_collection}/{filename} i:{remote_home_collection}/{filename}".format(**parameters))

			# check that file is on remote zone's resource hierarchy
			test_session.assert_icommand(
				"ils -L {remote_home_collection}/{filename}".format(**parameters),  'STDOUT_MULTILINE', [filename, parameters['remote_pt_resc_hier']])

			# get file back and compare checksums
			if test.settings.FEDERATION.REMOTE_IRODS_VERSION != (4, 0, 3):
				test_session.assert_icommand(
					"iget {remote_home_collection}/{filename} {filepath}".format(**parameters))
				new_md5 = lib.file_digest(filepath, 'md5')
				self.assertEqual(orig_md5, new_md5)
			else:
				test_session.assert_icommand(
					"iget {remote_home_collection}/{filename} {filepath}".format(**parameters), 'STDERR_SINGLELINE', 'USER_RODS_HOSTNAME_ERR')

		finally:
			# cleanup
			test_session.run_icommand(
				"irm -f {local_home_collection}/{filename}".format(**parameters))
			test_session.run_icommand(
				"irm -f {remote_home_collection}/{filename}".format(**parameters))
			try:
				os.remove(filepath)
			except OSError:
				pass
			self.admin_sessions[0].run_icommand(
				"iadmin rmchildfromresc {local_pt_resc} {local_leaf_resc}".format(**parameters))
			self.admin_sessions[0].run_icommand(
				"iadmin rmresc {local_pt_resc}".format(**parameters))
			self.admin_sessions[0].run_icommand(
				"iadmin rmresc {local_leaf_resc}".format(**parameters))

	def test_ilsresc_z(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# list remote resources
		test_session.assert_icommand(
			"ilsresc --ascii -z {remote_zone}".format(**self.config), 'STDOUT_SINGLELINE', test.settings.FEDERATION.REMOTE_DEF_RESOURCE)

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 0) or test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 0, 0), 'No resource hierarchies before iRODS 4')
	def test_ilsresc_z_child_resc(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]
		test_session.assert_icommand(
			"ilsresc --ascii -z {remote_zone}".format(**self.config), 'STDOUT_SINGLELINE', test.settings.FEDERATION.REMOTE_PT_RESC_HIER.split(';')[1])

	def run_remote_writeLine_test(self, config, zone_info):
		# Some inputs and expected values
		localnum_before = 1
		localnum_after = 3
		localstring = 'one'
		inputnum_before = 4
		inputnum_after = 6
		inputstring = 'four'
		remotenum = 0
		remotestring = 'zero'
		expected_before_remote = 'stdout before remote: {0}, {1}, {2}, {3}'.format(
			inputnum_before, inputstring, localnum_before, localstring)
		expected_from_remote = 'stdout from remote: {0}, {1}, {2}, {3}, {4}, {5}'.format(
			inputnum_before, inputstring, localnum_before, localstring, remotenum, remotestring)
		expected_after_remote = 'stdout after remote: {0}, {1}, {2}, {3}'.format(
			inputnum_after, inputstring, localnum_after, localstring)

		if zone_info == 'local':
			zone = config['local_zone']
			host = socket.gethostname()
			# TODO: Add support for remote with #4164
			expected_from_remote_log = 'serverLog from remote: {0}, {1}, {2}, {3}, {4}, {5}'.format(
				inputnum_before, inputstring, localnum_before, localstring, remotenum, remotestring)
		else:
			zone = config['remote_zone']
			host = config['remote_host']

		# Write a line to the serverLog in the local zone using remote execution block
		rule_string = '''
myTestRule {{
	*localnum = {0};
	*localstring = "{1}";
	writeLine("stdout", "stdout before remote: *inputnum, *inputstring, *localnum, *localstring");
	remote("{2}", "<ZONE>{3}</ZONE>") {{
		*remotenum = {4};
		*remotestring = "{5}";
		writeLine("serverLog", "serverLog from remote: *inputnum, *inputstring, *localnum, *localstring, *remotenum, *remotestring");
		writeLine("stdout", "stdout from remote: *inputnum, *inputstring, *localnum, *localstring, *remotenum, *remotestring");
		*inputnum = *inputnum + 1
		*localnum = *localnum + 1
	}}
	*inputnum = *inputnum + 1
	*localnum = *localnum + 1
	writeLine("stdout", "stdout after remote: *inputnum, *inputstring, *localnum, *localstring");
}}
INPUT *inputnum={6}, *inputstring="{7}"
OUTPUT ruleExecOut
			'''.format(localnum_before, localstring, host, zone, remotenum, remotestring, inputnum_before, inputstring)

		rule_file = "test_rule_file.r"
		with open(rule_file, 'w') as f:
			f.write(rule_string)

		# TODO: Add support for remote with #4164
		if zone_info == 'local':
			initial_log_size = lib.get_file_size_by_path(paths.server_log_path())

		# Execute rule and ensure that output is empty (success)
		self.user_sessions[0].assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-irods_rule_language-instance', '-F', rule_file],
			'STDOUT_MULTILINE', [expected_before_remote, expected_from_remote, expected_after_remote])

		# TODO: Add support for remote with #4164
		if zone_info == 'local':
			lib.delayAssert(
				lambda: lib.log_message_occurrences_equals_count(
					msg=expected_from_remote_log,
					start_index=initial_log_size))
		os.remove(rule_file)

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 3) or test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 2, 3), 'Fixed in 4.2.3')
	def test_remote_writeLine_localzone_3722(self):
		self.run_remote_writeLine_test(self.config.copy(), 'local')

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 3) or test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 2, 3), 'Fixed in 4.2.3')
	def test_remote_writeLine_remotezone_3722(self):
		self.run_remote_writeLine_test(self.config.copy(), 'remote')

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 9) or test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 2, 9), 'Only available in 4.2.9 and later')
	def test_federation_support_for_replica_open_close_and_get_file_descriptor_info(self):
		user = self.user_sessions[0]
		parameters = self.config.copy()

		# Create a new data object via istream.
		# istream proves that the following API plugins work in a federated environment.
		# - rx_get_file_descriptor_info
		# - rx_replica_open
		# - rx_replica_close
		parameters['filename'] = 'istream_test_file.txt'
		parameters['user_name'] = user.username
		parameters['remote_home_collection'] = '/{remote_zone}/home/{user_name}#{local_zone}'.format(**parameters)
		parameters['remote_data_object'] = '{remote_home_collection}/{filename}'.format(**parameters)
		contents = 'Hello, iRODS!'
		try:
			user.assert_icommand('istream write {remote_data_object}'.format(**parameters), input=contents)

			# Show that the data object exists and contains the expected content.
			user.assert_icommand('istream read {remote_data_object}'.format(**parameters), 'STDOUT', [contents])

		finally:
			user.run_icommand(['irm', '-f', parameters['remote_data_object']])

	def test_itouch__issue_6849(self):
		user = self.user_sessions[0]
		parameters = self.config.copy()

		parameters['filename'] = 'itouch_test_file.txt'
		parameters['user_name'] = user.username
		parameters['remote_home_collection'] = '/{remote_zone}/home/{user_name}#{local_zone}'.format(**parameters)
		parameters['remote_data_object'] = '{remote_home_collection}/{filename}'.format(**parameters)

		try:
			user.assert_icommand('itouch {remote_data_object}'.format(**parameters))
			user.assert_icommand('ils {remote_data_object}'.format(**parameters), 'STDOUT', [parameters['remote_data_object']])

		finally:
			user.run_icommand(['irm', '-f', parameters['remote_data_object']])


	def test_catalog_provider_hosts_other_than_the_first_are_considered__issue_6827(self):
		import json

		user = self.user_sessions[0]
		remote_zone = self.config['remote_zone']
		local_zone = self.config['local_zone']
		remote_home_collection = os.path.join('/{}'.format(remote_zone), 'home', '#'.join([user.username, local_zone]))

		# Control case: Make sure we can list the contents in the remote zone...
		user.assert_icommand(['ils', '-l', remote_home_collection], 'STDOUT')

		# Get the current server configuration so we can make changes
		server_config_filename = paths.server_config_path()
		with open(server_config_filename) as f:
			svr_cfg = json.load(f)

		# Add a dummy entry to the beginning of the catalog_provider_hosts which will not resolve.
		remote_provider_host = svr_cfg['federation'][0]['catalog_provider_hosts'][0]
		svr_cfg['federation'][0]['catalog_provider_hosts'][0] = 'keeplookinbuddy'

		new_server_config = json.dumps(svr_cfg, sort_keys=True, indent=4, separators=(',', ': '))

		try:
			with lib.file_backed_up(server_config_filename):
				# Repave the existing server_config.json. It will be restored when we leave this 'with' block.
				with open(server_config_filename, 'w') as f:
					f.write(new_server_config)
				IrodsController().reload_configuration()

				# If the hostname is not found in the catalog_provider_hosts list, the remote server will sign its local
				# zone key with its local negotiation key and the signed zone key sent by the local server will not match
				# that signed zone key.
				user.assert_icommand(['ils', '-l', remote_home_collection], 'STDERR', 'ZONE_KEY_SIGNATURE_MISMATCH')

			# Now add the valid hostname to the end of the list so that the zone key will be correctly signed.
			svr_cfg['federation'][0]['catalog_provider_hosts'].append(remote_provider_host)

			# Dump to a string to repave the existing server_config.json.
			new_server_config = json.dumps(svr_cfg, sort_keys=True, indent=4, separators=(',', ': '))
			with lib.file_backed_up(server_config_filename):
				# Repave the existing server_config.json. It will be restored when we leave this 'with' block.
				with open(server_config_filename, 'w') as f:
					f.write(new_server_config)
				IrodsController().reload_configuration()

				# Ensure that we can still list the contents in the remote zone because the server negotiation logic looked
				# at all the entries in the catalog_provider_hosts (not just the first one).
				user.assert_icommand(['ils', '-l', remote_home_collection], 'STDOUT')

		finally:
			IrodsController().reload_configuration()


	def test_remove_data_object_in_collection_with_read_permissions__issue_6428(self):
		def get_collection_mtime(session, collection_path):
			return session.run_icommand(['iquest', '%s',
				"select COLL_MODIFY_TIME where COLL_NAME = '{}'".format(collection_path)])[0].strip()

		user = self.user_sessions[0]
		filename = 'issue_6428_object'
		collection_name = 'issue_6428_collection'
		collection_path = os.path.join('/' + test.settings.FEDERATION.REMOTE_ZONE, 'home', 'public', collection_name)
		logical_path = os.path.join(collection_path, filename)

		with session.make_session_for_existing_user(test.settings.PREEXISTING_ADMIN_USERNAME,
													test.settings.PREEXISTING_ADMIN_PASSWORD,
													test.settings.FEDERATION.REMOTE_HOST,
													test.settings.FEDERATION.REMOTE_ZONE) as owner:
			try:
				owner.assert_icommand(['imkdir', collection_path])
				owner.assert_icommand(['itouch', logical_path])
				owner.assert_icommand(['ichmod', 'read', user.qualified_username, collection_path])
				owner.assert_icommand(['ichmod', 'own', user.qualified_username, logical_path])
				self.assertTrue(lib.replica_exists(user, logical_path, 0))

				original_mtime = get_collection_mtime(owner, collection_path)

				# Sleep here so that the collection mtime is guaranteed to be different if updated correctly.
				time.sleep(1)

				user.assert_icommand(['irm', logical_path])
				self.assertFalse(lib.replica_exists(user, logical_path, 0))

				new_mtime = get_collection_mtime(owner, collection_path)

				self.assertNotEqual(original_mtime, new_mtime, msg='collection mtime was not updated')

			finally:
				owner.assert_icommand(['ils', '-Al', collection_path], 'STDOUT') # Debugging

				user.assert_icommand(['irmtrash'])
				owner.assert_icommand(['irm', '-r', '-f', collection_path])
				owner.assert_icommand(['irmtrash', '-M'])


class Test_Admin_Commands(unittest.TestCase):

	'''
	Operations requiring administrative privilege,
	run in the remote zone by a local rodsadmin.
	They should all fail (disallowed by remote zone).
	'''

	def setUp(self):
		# make session with existing admin account
		self.admin_session = session.make_session_for_existing_admin()

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val
		self.config['local_zone'] = self.admin_session.zone_name

		super(Test_Admin_Commands, self).setUp()

	def tearDown(self):
		self.admin_session.__exit__()
		super(Test_Admin_Commands, self).tearDown()

	def test_ichmod(self):
		# test specific parameters
		parameters = self.config.copy()
		parameters['user_name'] = self.admin_session.username

		# try to modify ACLs in the remote zone
		self.admin_session.assert_icommand(
			"ichmod -rM own {user_name}#{local_zone} /{remote_zone}/home".format(**parameters), 'STDERR_SINGLELINE', 'CAT_NO_ACCESS_PERMISSION')

		self.admin_session.assert_icommand(
			"ichmod -M own {user_name} /{remote_zone}/home".format(**parameters), 'STDERR_SINGLELINE', 'CAT_NO_ACCESS_PERMISSION')

		self.admin_session.assert_icommand(
			"ichmod -M read {user_name} /{remote_zone}".format(**parameters), 'STDERR_SINGLELINE', 'CAT_NO_ACCESS_PERMISSION')

	def test_iadmin(self):
		pass


class Test_Microservices(SessionsMixin, unittest.TestCase):

	def setUp(self):
		super(Test_Microservices, self).setUp()

		# make local test directory
		self.local_test_dir_path = os.path.abspath('federation_test_stuff.tmp')
		os.mkdir(self.local_test_dir_path)

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val
		self.config['local_zone'] = self.user_sessions[0].zone_name

	def tearDown(self):
		# remove test directory
		shutil.rmtree(self.local_test_dir_path)

		super(Test_Microservices, self).tearDown()

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 1, 0), 'Fixed in 4.1.0')
	def test_msirmcoll(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test dir
		dir_name = 'msiRmColl_test_dir'
		dir_path = os.path.join(self.local_test_dir_path, dir_name)
		local_files = lib.make_large_local_tmp_dir(
			dir_path, self.config['test_file_count'], self.config['test_file_size'])

		# test specific parameters
		parameters = self.config.copy()
		parameters['dir_path'] = dir_path
		parameters['dir_name'] = dir_name
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put dir in remote collection
		test_session.assert_icommand(
			"iput -r {dir_path} {remote_home_collection}/".format(**parameters))

		# new collection should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDOUT_SINGLELINE', dir_name)

		# files should be there
		rods_files = set(test_session.get_entries_in_collection("{remote_home_collection}/{dir_name}".format(**parameters)))
		self.assertTrue(set(local_files) == rods_files)

		# prepare irule sequence
		# the rule is simple enough not to need a rule file
		irule_str = '''irule -r irods_rule_engine_plugin-irods_rule_language-instance "msiRmColl(*coll, 'forceFlag=', *status); writeLine('stdout', *status)" "*coll={remote_home_collection}/{dir_name}" "ruleExecOut"'''.format(
			**parameters)

		# invoke msiRmColl() and checks that it returns 0
		test_session.assert_icommand(
			irule_str, 'STDOUT', '^0$', use_regex=True)

		# collection should be gone
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{dir_name}".format(**parameters), 'STDERR_SINGLELINE', 'does not exist')

		# cleanup
		shutil.rmtree(dir_path)

	def test_delay_msiobjstat(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'delay_msiobjstat_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)

		# put file in remote collection
		test_session.assert_icommand(
			"iput -f {filepath} {remote_home_collection}/".format(**parameters))

		# file should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', filename)

		# prepare rule file
		rule_file_path = os.path.join(
			self.local_test_dir_path, 'delay_msiobjstat.r')
		with open(rule_file_path, 'wt') as rule_file:
			rule_str = '''
delay_msiobjstat {{
	delay("<PLUSET>30s</PLUSET>") {{
# Perform a stat on the object
# Save the stat operation's error code as metadata associated with the object
		*attr."delay_msiobjstat_return_value" = str(errorcode(msiObjStat(*obj,*out)));
		msiAssociateKeyValuePairsToObj(*attr, *obj, "-d")
	}}
}}
INPUT *obj="{remote_home_collection}/{filename}"
OUTPUT ruleExecOut
'''.format(**parameters)
			print(rule_str, file=rule_file, end='')

		# invoke rule
		test_session.assert_icommand('irule -r irods_rule_engine_plugin-irods_rule_language-instance -F ' + rule_file_path)

		# give it time to complete
		time.sleep(60)

		# look for AVU set by delay rule
		attr = "delay_msiobjstat_return_value"
		value = "0"
		test_session.assert_icommand('imeta ls -d {remote_home_collection}/{filename}'.format(
			**parameters), 'STDOUT_MULTILINE', ['attribute: ' + attr + '$', 'value: ' + value + '$'], use_regex=True)

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))
		os.remove(filepath)

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 1, 5), 'Fixed in 4.1.5')
	def test_msiRemoveKeyValuePairsFromObj(self):
		# pick session(s) for the test
		test_session = self.user_sessions[0]

		# make test file
		filename = 'msiRemoveKeyValuePairsFromObj_test_file'
		filesize = self.config['test_file_size']
		filepath = os.path.join(self.local_test_dir_path, filename)
		lib.make_file(filepath, filesize)

		# test specific parameters
		parameters = self.config.copy()
		parameters['filepath'] = filepath
		parameters['filename'] = filename
		parameters['user_name'] = test_session.username
		parameters['remote_home_collection'] = "/{remote_zone}/home/{user_name}#{local_zone}".format(
			**parameters)
		parameters['attribute'] = "test_attr"
		parameters['value'] = "test_value"

		# put file in remote collection
		test_session.assert_icommand(
			"iput -f {filepath} {remote_home_collection}/".format(**parameters))

		# file should be there
		test_session.assert_icommand(
			"ils -L {remote_home_collection}/{filename}".format(**parameters), 'STDOUT_SINGLELINE', filename)

		# prepare first rule file to add kvp metadata
		rule_file_path = os.path.join(
			self.local_test_dir_path, 'msiAssociateKeyValuePairsToObj.r')
		with open(rule_file_path, 'w') as rule_file:
			rule_str = '''
msiAssociateKeyValuePairsToObj {{
	*attr."{attribute}" = "{value}";
	msiAssociateKeyValuePairsToObj(*attr, *obj, "-d")
}}
INPUT *obj="{remote_home_collection}/{filename}"
OUTPUT ruleExecOut
'''.format(**parameters)
			rule_file.write(rule_str)

		# invoke rule
		test_session.assert_icommand('irule -r irods_rule_engine_plugin-irods_rule_language-instance -F ' + rule_file_path)

		# look for AVU set by msiAssociateKeyValuePairsToObj
		test_session.assert_icommand(
									 'imeta ls -d {remote_home_collection}/{filename}'.format(**parameters),
									 'STDOUT_MULTILINE',
									 ['attribute: {attribute}$'.format(**parameters),
									  'value: {value}$'.format(**parameters)],
									 use_regex=True)

		# prepare second rule file to remove kvp metadata
		rule_file_path = os.path.join(
			self.local_test_dir_path, 'msiRemoveKeyValuePairsFromObj.r')
		with open(rule_file_path, 'w') as rule_file:
			rule_str = '''
msiRemoveKeyValuePairsFromObj {{
	*attr."{attribute}" = "{value}";
	msiRemoveKeyValuePairsFromObj(*attr, *obj, "-d")
}}
INPUT *obj="{remote_home_collection}/{filename}"
OUTPUT ruleExecOut
'''.format(**parameters)
			rule_file.write(rule_str)

		# invoke rule
		test_session.assert_icommand('irule -r irods_rule_engine_plugin-irods_rule_language-instance -F ' + rule_file_path)

		# confirm that AVU is gone
		test_session.assert_icommand(
									 'imeta ls -d {remote_home_collection}/{filename}'.format(**parameters),
									 'STDOUT_MULTILINE',
									 ['AVUs defined for dataObj {remote_home_collection}/{filename}:$'.format(**parameters),
									  'None$'],
									 use_regex=True)

		# cleanup
		test_session.assert_icommand(
			"irm -f {remote_home_collection}/{filename}".format(**parameters))
		os.remove(filepath)

class Test_Recursive_Icp(SessionsMixin, unittest.TestCase):

	def setUp(self):
		super(Test_Recursive_Icp, self).setUp()

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val
		self.config['local_zone'] = self.user_sessions[0].zone_name

		# Use 10 files; expected value is -1 due to 0-based indexing
		self.file_count1 = 10
		self.file_count2 = self.file_count1 * 2
		self.local_dir1 = 'test_recursive_icp1'
		self.local_dir2 = 'test_recursive_icp2'
		lib.create_directory_of_small_files(self.local_dir1, self.file_count1)
		lib.create_directory_of_small_files(self.local_dir2, self.file_count2)

		test_session = self.user_sessions[0]
		source_coll_name = 'source_coll'
		self.local_source_coll = os.path.join(test_session.home_collection, source_coll_name)
		test_session.assert_icommand(['imkdir', self.local_source_coll])

		test_session.assert_icommand(['irsync', '-r', self.local_dir1, self.local_dir2, 'i:{}'.format(self.local_source_coll)])

	def tearDown(self):
		test_session = self.user_sessions[0]
		test_session.assert_icommand(['irm', '-rf', self.local_source_coll])
		shutil.rmtree(self.local_dir1)
		shutil.rmtree(self.local_dir2)
		super(Test_Recursive_Icp, self).tearDown()

	# recursive icp of local source collection
	def cp_recursive_local_source_test(self, source_coll, flat_coll=True, remote_zone=True, in_target=False):
		test_session = self.user_sessions[0]
		try:
			# prepare names for home collection and target collection
			if remote_zone:
				home_coll = test_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
			else:
				home_coll = test_session.home_collection
			target_coll = os.path.join(home_coll, 'cp_recursive_local_source_test')
			# create target collection and copy source into it
			test_session.assert_icommand(['imkdir', target_coll])
			if in_target:
				test_session.assert_icommand(['icd', target_coll])
				test_session.assert_icommand(['icp', '-r', source_coll, '.'])
			else:
				test_session.assert_icommand(['icp', '-r', source_coll, target_coll])
			# ensure all files are in the collection
			test_session.assert_icommand(['ils', '-lr', target_coll], 'STDOUT_SINGLELINE', '& {}'.format(str(self.file_count1 - 1)))
			if flat_coll:
				test_session.assert_icommand_fail(['ils', '-lr', target_coll], 'STDOUT_SINGLELINE', '& {}'.format(str(self.file_count2 - 1)))
			else:
				test_session.assert_icommand(['ils', '-lr', target_coll], 'STDOUT_SINGLELINE', '& {}'.format(str(self.file_count2 - 1)))
		finally:
			# cleanup
			test_session.assert_icommand(['irm', '-rf', target_coll])

	def test_icp_single_dir_localzone_in_home(self):
		source_coll = os.path.join(self.local_source_coll, self.local_dir1)
		self.cp_recursive_local_source_test(source_coll, flat_coll=True, remote_zone=False, in_target=False)

	def test_icp_single_dir_localzone_in_target(self):
		source_coll = os.path.join(self.local_source_coll, self.local_dir1)
		self.cp_recursive_local_source_test(source_coll, flat_coll=True, remote_zone=False, in_target=True)

	def test_icp_single_dir_remotezone_in_home(self):
		source_coll = os.path.join(self.local_source_coll, self.local_dir1)
		self.cp_recursive_local_source_test(source_coll, flat_coll=True, remote_zone=True, in_target=False)

	def test_icp_single_dir_remotezone_in_target(self):
		source_coll = os.path.join(self.local_source_coll, self.local_dir1)
		self.cp_recursive_local_source_test(source_coll, flat_coll=True, remote_zone=True, in_target=True)

	def test_icp_tree_localzone_in_home(self):
		self.cp_recursive_local_source_test(self.local_source_coll, flat_coll=False, remote_zone=False, in_target=False)

	def test_icp_tree_localzone_in_target(self):
		self.cp_recursive_local_source_test(self.local_source_coll, flat_coll=False, remote_zone=False, in_target=True)

	def test_icp_tree_remotezone_in_home(self):
		self.cp_recursive_local_source_test(self.local_source_coll, flat_coll=False, remote_zone=True, in_target=False)

	def test_icp_tree_remotezone_in_target(self):
		self.cp_recursive_local_source_test(self.local_source_coll, flat_coll=False, remote_zone=True, in_target=True)

class test_dynamic_peps_in_federation(SessionsMixin, unittest.TestCase):
	plugin_name = IrodsConfig().default_rule_engine_plugin
	class_name = 'Test_Native_Rule_Engine_Plugin'

	def setUp(self):
		super(test_dynamic_peps_in_federation, self).setUp()

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val

		self.config['local_zone'] = self.user_sessions[0].zone_name
		if test.settings.FEDERATION.REMOTE_IRODS_VERSION < (4, 0, 0):
			test.settings.FEDERATION.REMOTE_VAULT = '/home/irods/irods-legacy/iRODS/Vault'

		self.admin = session.make_session_for_existing_admin()

	def tearDown(self):
		self.admin.__exit__()
		super(test_dynamic_peps_in_federation, self).tearDown()

	@unittest.skipIf(IrodsConfig().version_tuple < (4, 2, 9), 'Fixed in 4.2.9')
	def test_peps_for_parallel_mode_transfers__issue_5017(self):
		test_session = self.user_sessions[0]
		remote_home_collection = test_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
		filename = 'test_peps_for_parallel_mode_transfers__issue_5017'
		local_file = os.path.join(self.admin.local_session_dir, filename)
		logical_path = os.path.join(remote_home_collection, filename)
		local_logical_path = os.path.join(test_session.home_collection, filename)
		file_size = 40 * 1024 * 1024 # 40MB
		attr = 'test_peps_for_parallel_mode_transfers__issue_5017'

		try:
			if not os.path.exists(local_file):
				lib.make_file(local_file, file_size)

			# PEPs will fire locally on connected server, so metadata will be applied to local data object
			parameters = {}
			parameters['logical_path'] = local_logical_path
			put_peps = '''
pep_api_data_obj_put_pre (*INSTANCE_NAME, *COMM, *DATAOBJINP, *BUFFER, *PORTAL_OPR_OUT)
{{
	msiAddKeyVal(*key_val_pair,"test_peps_for_parallel_mode_transfers__issue_5017","data-obj-put-pre");
	msiAssociateKeyValuePairsToObj(*key_val_pair,"{logical_path}","-d");
}}
pep_api_data_obj_put_post (*INSTANCE_NAME, *COMM, *DATAOBJINP, *BUFFER, *PORTAL_OPR_OUT)
{{
	msiAddKeyVal(*key_val_pair,"test_peps_for_parallel_mode_transfers__issue_5017","data-obj-put-post");
	msiAssociateKeyValuePairsToObj(*key_val_pair,"{logical_path}","-d");
}}
pep_api_data_obj_put_except (*INSTANCE_NAME, *COMM, *DATAOBJINP, *BUFFER, *PORTAL_OPR_OUT)
{{
	msiAddKeyVal(*key_val_pair,"test_peps_for_parallel_mode_transfers__issue_5017","data-obj-put-except");
	msiAssociateKeyValuePairsToObj(*key_val_pair,"{logical_path}","-d");
}}
pep_api_data_obj_put_finally (*INSTANCE_NAME, *COMM, *DATAOBJINP, *BUFFER, *PORTAL_OPR_OUT)
{{
	msiAddKeyVal(*key_val_pair,"test_peps_for_parallel_mode_transfers__issue_5017","data-obj-put-finally");
	msiAssociateKeyValuePairsToObj(*key_val_pair,"{logical_path}","-d");
}}
'''.format(**parameters)

			print(put_peps)

			# put a new data object so that the PEPs have an object to which metadata can be associated
			test_session.assert_icommand(['iput', local_file, local_logical_path])

			with temporary_core_file() as core:
				core.add_rule(put_peps)
				IrodsController().reload_configuration()

				# peps to check for the first, successful put
				peps = ['data-obj-put-pre', 'data-obj-put-post', 'data-obj-put-finally']

				# put a new data object and ensure success
				test_session.assert_icommand(['iput', local_file, logical_path])

				for pep in peps:
					lib.delayAssert(
						lambda: lib.metadata_attr_with_value_exists(test_session, attr, pep),
						interval=1,
						maxrep=10
					)

				self.assertFalse(lib.metadata_attr_with_value_exists(test_session, attr, 'pep-obj-put-except'))

				# clean up metadata for next test
				for pep in peps:
					test_session.assert_icommand(['imeta', 'rm', '-d', local_logical_path, attr, pep])

				test_session.assert_icommand(['imeta', 'ls', '-d', local_logical_path], 'STDOUT', 'None')

				# peps to check for the second, unsuccessful put
				peps = ['data-obj-put-pre', 'data-obj-put-except', 'data-obj-put-finally']

				# put to same logical path without force flag, resulting in error and (hopefully) triggering except PEP
				test_session.assert_icommand(['iput', local_file, logical_path], 'STDERR', 'OVERWRITE_WITHOUT_FORCE_FLAG')

				for pep in peps:
					lib.delayAssert(
						lambda: lib.metadata_attr_with_value_exists(test_session, attr, pep),
						interval=1,
						maxrep=10
					)

				self.assertFalse(lib.metadata_attr_with_value_exists(test_session, attr, 'pep-obj-put-post'))

		finally:
			test_session.run_icommand(['irm', '-f', local_logical_path])
			test_session.run_icommand(['irm', '-f', logical_path])
			self.admin.assert_icommand(['iadmin', 'rum'])

			IrodsController().reload_configuration()

class Test_Delay_Rule_Removal(SessionsMixin, unittest.TestCase):

	# This test suite expects tempZone to contain the following users:
	#
	#   - rods#tempZone
	#   - zonehopper#tempZone (created by the irods_testing_environment)
	#   - zonehopper#otherZone (created by the irods_testing_environment)
	#
	# otherZone must contain the following users:
	#
	#   - rods#otherZone
	#
	# The test suite must be launched from a server in otherZone. That means tempZone
	# is identified as the remote federated zone.
	#
	# Just before the tests are run, the base class will create three additional users
	# in otherZone. The following users will appear:
	#
	#   - admin#otherZone
	#   - zonehopper#otherZone
	#   - zonehopper#tempZone (created by setUp())

	plugin_name = IrodsConfig().default_rule_engine_plugin

	def setUp(self):
		super(Test_Delay_Rule_Removal, self).setUp()

		# session.make_sessions_mixin() creates admins and users that connect to the host
		# identified by lib.get_hostname().
		#
		# For this particular set of tests, that means these users connect to the host where
		# "otherZone" runs.
		self.local_admin = self.admin_sessions[0] # admin#otherZone
		self.local_user = self.user_sessions[0]   # zonehopper#otherZone

		# Create session for zonehopper#tempZone. The session will be connected to tempZone.
		password = test.settings.FEDERATION.RODSUSER_NAME_PASSWORD_LIST[0][1]
		host = test.settings.FEDERATION.REMOTE_HOST
		zone = test.settings.FEDERATION.REMOTE_ZONE
		self.remote_user = session.make_session_for_existing_user(self.local_user.username, password, host, zone)

		# Create zonehopper#tempZone in otherZone. This must be handled by the test suite rather
		# than the session.make_sessions_mixin() because that function only knows about the local zone.
		self.remote_user_home_collection = self.remote_user.remote_home_collection(self.local_user.zone_name)
		self.local_admin.assert_icommand(['iadmin', 'mkuser', self.remote_user.qualified_username, 'rodsuser'])

		# Validity check: If the remote user's home collection does not exist in the zone these tests
		# are run from, then the testing environment is in a bad state.
		self.local_admin.assert_icommand(['ils', self.remote_user_home_collection], 'STDOUT', [self.remote_user.qualified_username])

		# Make sure there are no left over delay rules.
		self.local_admin.run_icommand(['iqdel', '-a'])

	def tearDown(self):
		self.remote_user.__exit__()
		self.local_admin.run_icommand(['iadmin', 'rmuser', self.remote_user.qualified_username])
		super(Test_Delay_Rule_Removal, self).tearDown()

	@unittest.skipIf(plugin_name == 'irods_rule_engine_plugin-python', 'Skip if testing the PREP')
	def test_local_zone_user_is_not_allowed_to_delete_delay_rules_created_by_remote_user_with_the_same_username__issue_6482(self):
		try:
			with temporary_core_file() as core_re:
				# Users in a federated environment are not allowed to create delay rules in the
				# remote zone directly. Remote users can only create delay rules indirectly
				# (e.g. through a PEP in the federated zone).
				core_re.add_rule(dedent('''
					pep_api_touch_pre(*a, *b, *c)
					{
						delay("<INST_NAME>irods_rule_engine_plugin-irods_rule_language-instance</INST_NAME><PLUSET>3600s</PLUSET>") {
							writeLine("serverLog", "#6482");
						}
					}
				'''))
				IrodsController().reload_configuration()

				# Trigger the PEP so that a delay rule is created.
				self.remote_user.assert_icommand(['itouch', self.remote_user_home_collection])

				# For debug purposes (allows developers to see the delay rule in the test output).
				self.local_admin.assert_icommand(['iqstat', '-a'], 'STDOUT')

			# Capture the ID of the new delay rule.
			rule_id = lib.get_first_delay_rule_id(self.local_admin)

			# Show that the local zone user cannot delete a remote zone user's rule by ID even when
			# they share identical unqualified usernames.
			expected_error_msg = ['rcRuleExecDel failed with error -350000 USER_ACCESS_DENIED']
			self.local_user.assert_icommand(['iqdel', rule_id], 'STDERR_SINGLELINE', expected_error_msg)

			# Show that the local user cannot delete a remote zone user's rule by username either.
			self.local_user.assert_icommand(['iqdel', '-u', self.remote_user.username], 'STDERR_SINGLELINE', expected_error_msg)

		finally:
			self.local_admin.run_icommand(['iqdel', '-a'])
			IrodsController().reload_configuration()


class test_compound_resource_operations(SessionsMixin, unittest.TestCase):
	def setUp(self):
		super(test_compound_resource_operations, self).setUp()

		# load federation settings in dictionary (all lower case)
		self.config = {}
		for key, val in test.settings.FEDERATION.__dict__.items():
			if not key.startswith('__'):
				self.config[key.lower()] = val
		self.config['local_zone'] = self.user_sessions[0].zone_name

		self.admin = self.admin_sessions[0]
		self.user = self.user_sessions[0]

		# Create a session as the administrator for the remote zone so we can create resources in the remote zone.
		self.remote_admin = session.make_session_for_existing_user(
			test.settings.PREEXISTING_ADMIN_USERNAME,
			test.settings.PREEXISTING_ADMIN_PASSWORD,
			test.settings.FEDERATION.REMOTE_HOST,
			test.settings.FEDERATION.REMOTE_ZONE)

		# Create a regular user local to the remote zone in the remote zone and create a session for it.
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', 'smeagol', 'rodsuser'])
		self.remote_admin.assert_icommand(['iadmin', 'moduser', 'smeagol', 'password', 'spass'])
		self.remote_user = session.IrodsSession(
			lib.make_environment_dict(
				'smeagol',
				test.settings.FEDERATION.REMOTE_HOST,
				test.settings.FEDERATION.REMOTE_ZONE,
				use_ssl=test.settings.USE_SSL
			),
			'spass',
			manage_irods_data=True)

		# Create a compound resource hierarchy in the remote zone.
		self.compound_resource = 'compResc'
		self.cache_resource = 'cacheResc'
		self.archive_resource = 'archiveResc'
		self.remote_admin.assert_icommand(['iadmin', 'mkresc', self.compound_resource, 'compound'], 'STDOUT')
		lib.create_ufs_resource(self.remote_admin, self.cache_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)
		lib.create_ufs_resource(self.remote_admin, self.archive_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)
		self.remote_admin.assert_icommand(
			['iadmin', 'addchildtoresc', self.compound_resource, self.cache_resource, 'cache'])
		self.remote_admin.assert_icommand(
			['iadmin', 'addchildtoresc', self.compound_resource, self.archive_resource, 'archive'])


	def tearDown(self):
		# Exit the remote user session so it can be cleaned it up.
		self.remote_user.__exit__()
		self.remote_admin.assert_icommand(['iadmin', 'rmuser', 'smeagol'])

		# Clean up the compound resource hierarchy and exit the remote admin session.
		lib.remove_child_resource(self.remote_admin, self.compound_resource, self.cache_resource)
		lib.remove_child_resource(self.remote_admin, self.compound_resource, self.archive_resource)
		lib.remove_resource(self.remote_admin, self.cache_resource)
		lib.remove_resource(self.remote_admin, self.archive_resource)
		lib.remove_resource(self.remote_admin, self.compound_resource)

		self.remote_admin.__exit__()

		super(test_compound_resource_operations, self).tearDown()

	def assert_permissions_on_data_object_for_user(self, username, zone_name, logical_path, permission_value):
		data_access_type = self.remote_admin.run_icommand(['iquest', '%s',
			'select DATA_ACCESS_TYPE where '
				'COLL_NAME = \'{}\' and '
				'DATA_NAME = \'{}\' and '
				'USER_NAME = \'{}\' and '
				'USER_ZONE = \'{}\''.format(
					os.path.dirname(logical_path), os.path.basename(logical_path), username, zone_name)
			])[0].strip()

		self.assertEqual(str(data_access_type), str(permission_value))

	def test_iget_data_object_as_user_with_read_only_access_and_replica_only_in_archive__issue_6697(self):
		cache_hierarchy = self.compound_resource + ';' + self.cache_resource
		archive_hierarchy = self.compound_resource + ';' + self.archive_resource

		owner_user = self.remote_user
		readonly_user = self.user
		filename = 'foo'
		contents = 'jimbo'
		logical_path = os.path.join(owner_user.session_collection, filename)

		try:
			# Create a data object which should appear under the compound resource.
			owner_user.assert_icommand(['istream', '-R', self.compound_resource, 'write', logical_path], input=contents)
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.cache_resource))
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.archive_resource))

			# Grant read access to another user, ensuring that the other user can see the data object.
			owner_user.assert_icommand(
				['ichmod', '-r', 'read', readonly_user.qualified_username, os.path.dirname(logical_path)])

			# Ensure that the read-only user has read-only permission on the data object.
			self.assert_permissions_on_data_object_for_user(
				readonly_user.username, readonly_user.zone_name, logical_path, 1050)

			# Trim the replica on the cache resource so that only the replica in the archive remains. Replica 0 resides
			# on the cache resource at this point.
			owner_user.assert_icommand(['itrim', '-N1', '-n0', logical_path], 'STDOUT')
			self.assertFalse(lib.replica_exists_on_resource(owner_user, logical_path, self.cache_resource))
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.archive_resource))

			# As the user with read-only access, attempt to get the data object. Replica 1 resides on the archive
			# resource, so the replica on the cache resource which results from the stage-to-cache should be number 2.
			readonly_user.assert_icommand(['iget', logical_path, '-'], 'STDOUT', contents)
			self.assertEqual(str(1), lib.get_replica_status(owner_user, os.path.basename(logical_path), 1))
			self.assertEqual(str(1), lib.get_replica_status(owner_user, os.path.basename(logical_path), 2))

			# Ensure that the user has the same permissions on the data object as before getting it.
			self.assert_permissions_on_data_object_for_user(
				readonly_user.username, readonly_user.zone_name, logical_path, 1050)

		finally:
			self.remote_admin.assert_icommand(['ils', '-Al', logical_path], 'STDOUT') # Debugging

			# Make sure that the data object can be removed by marking both replicas stale before removing.
			self.remote_admin.run_icommand(['ichmod', '-M', 'own', self.remote_admin.username, logical_path])
			self.remote_admin.run_icommand(
				['iadmin', 'modrepl', 'logical_path', logical_path, 'resource_hierarchy', cache_hierarchy, 'DATA_REPL_STATUS', '0'])
			self.remote_admin.run_icommand(
				['iadmin', 'modrepl', 'logical_path', logical_path, 'resource_hierarchy', archive_hierarchy, 'DATA_REPL_STATUS', '0'])
			self.remote_admin.run_icommand(['irm', '-f', logical_path])


	def test_iget_data_object_as_user_with_null_access_and_replica_only_in_archive__issue_6697(self):
		cache_hierarchy = self.compound_resource + ';' + self.cache_resource
		archive_hierarchy = self.compound_resource + ';' + self.archive_resource

		owner_user = self.remote_user
		no_access_user = self.user
		filename = 'foo'
		contents = 'jimbo'
		not_found_string = 'CAT_NO_ROWS_FOUND: Nothing was found matching your query'
		logical_path = os.path.join(owner_user.session_collection, filename)

		try:
			# Create a data object which should appear under the compound resource.
			owner_user.assert_icommand(['istream', '-R', self.compound_resource, 'write', logical_path], input=contents)
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.cache_resource))
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.archive_resource))

			# Ensure that the no-access user has no access permissions on the data object.
			self.assert_permissions_on_data_object_for_user(
				no_access_user.username, no_access_user.zone_name, logical_path, not_found_string)

			# Trim the replica on the cache resource so that only the replica in the archive remains. Replica 0 resides
			# on the cache resource at this point.
			owner_user.assert_icommand(['itrim', '-N1', '-n0', logical_path], 'STDOUT')
			self.assertFalse(lib.replica_exists_on_resource(owner_user, logical_path, self.cache_resource))
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.archive_resource))

			# As the user with no access, attempt to get the data object. This should fail, and stage-to-cache should
			# not occur. Confirm that no replica exists on the cache resource.
			no_access_user.assert_icommand(
				['iget', logical_path, '-'], 'STDERR', '{} does not exist'.format(logical_path))
			self.assertFalse(lib.replica_exists_on_resource(owner_user, logical_path, self.cache_resource))
			self.assertTrue(lib.replica_exists_on_resource(owner_user, logical_path, self.archive_resource))

			# Ensure that the no-access user still has no access permissions on the data object.
			self.assert_permissions_on_data_object_for_user(
				no_access_user.username, no_access_user.zone_name, logical_path, not_found_string)

		finally:
			self.remote_admin.assert_icommand(['ils', '-Al', logical_path], 'STDOUT') # Debugging

			# Make sure that the data object can be removed by marking both replicas stale before removing.
			self.remote_admin.run_icommand(['ichmod', '-M', 'own', self.remote_admin.username, logical_path])
			self.remote_admin.run_icommand(
				['iadmin', 'modrepl', 'logical_path', logical_path, 'resource_hierarchy', cache_hierarchy, 'DATA_REPL_STATUS', '0'])
			self.remote_admin.run_icommand(
				['iadmin', 'modrepl', 'logical_path', logical_path, 'resource_hierarchy', archive_hierarchy, 'DATA_REPL_STATUS', '0'])
			self.remote_admin.run_icommand(['irm', '-f', logical_path])


class test_icp_overwrite_with_target_resource(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		# Create a session as the administrator for the remote zone so we can do things in the remote zone.
		self.remote_admin = session.make_session_for_existing_user(
			test.settings.PREEXISTING_ADMIN_USERNAME,
			test.settings.PREEXISTING_ADMIN_PASSWORD,
			test.settings.FEDERATION.REMOTE_HOST,
			test.settings.FEDERATION.REMOTE_ZONE)

		# Create a user for testing in the local zone and a local user to represent the user in the remote zone created
		# above.
		local_user_name = 'qwerty'
		self.local_user = session.mkuser_and_return_session(
			'rodsuser', local_user_name, 'qpass', lib.get_hostname())

		# Create a user in the remote zone for use with the local zone's user. Don't give the user a password.
		self.local_user_remote_name = '#'.join([self.local_user.username, self.local_user.zone_name])
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', self.local_user_remote_name, 'rodsuser'])

		# Create a couple of resources in the local and remote zone for testing.
		self.remote_target_resource = 'remote_target_resource'
		self.remote_other_resource = 'remote_other_resource'
		lib.create_ufs_resource(
			self.remote_admin, self.remote_target_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)
		lib.create_ufs_resource(
			self.remote_admin, self.remote_other_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)

		self.local_target_resource = 'local_target_resource'
		self.local_other_resource = 'local_other_resource'
		with session.make_session_for_existing_admin() as admin_session:
			lib.create_ufs_resource(admin_session, self.local_target_resource, hostname=test.settings.HOSTNAME_2)
			lib.create_ufs_resource(admin_session, self.local_other_resource, hostname=test.settings.HOSTNAME_3)

	@classmethod
	def tearDownClass(self):
		# Clean up remote users, sessions, and resources.
		self.remote_admin.assert_icommand(['iadmin', 'rmuser', self.local_user_remote_name])
		lib.remove_resource(self.remote_admin, self.remote_target_resource)
		lib.remove_resource(self.remote_admin, self.remote_other_resource)
		self.remote_admin.__exit__()

		# Clean up local users, sessions, and resources.
		self.local_user.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.local_user.username])
			lib.remove_resource(admin_session, self.local_target_resource)
			lib.remove_resource(admin_session, self.local_other_resource)

	def successfully_overwrite_replica_on_target_resource_test_impl(self, copy_to, copy_from):
		"""A test which successfully overwrites a replica with icp while targeting a resource.

		Arguments:
		self - The test class.
		copy_to - The zone to copy to and overwrite a data object. Either "local" or "remote".
		copy_from - The zone from which a data object will be copied. Either "local" or "remote".
		"""
		# Use the session collection for the user in the appropriate "from" zone.
		user_session = self.local_user

		if copy_from == 'local':
			copy_from_collection = user_session.home_collection
		else:
			copy_from_collection = user_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)

		if copy_to == 'local':
			copy_to_collection = user_session.home_collection
			target_resource = self.local_target_resource
			other_resource = self.local_other_resource
		else:
			copy_to_collection = user_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
			target_resource = self.remote_target_resource
			other_resource = self.remote_other_resource

		copy_to_object_name = 'copy_to_object'
		copy_from_object_name = 'copy_from_object'
		copy_to_logical_path = os.path.join(copy_to_collection, copy_to_object_name)
		copy_from_logical_path = os.path.join(copy_from_collection, copy_from_object_name)

		original_content = 'the thing that bothers me is'
		new_content = 'someone keeps moving my chair'

		try:
			# Make an object and replicate to some target resource...
			user_session.assert_icommand(['istream', 'write', copy_to_logical_path], 'STDOUT', input=original_content)
			user_session.assert_icommand(['irepl', '-R', target_resource, copy_to_logical_path])

			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, target_resource))
			self.assertFalse(lib.replica_exists_on_resource(user_session, copy_to_logical_path, other_resource))

			# Make a new object with different content and copy over the first object (the copy should succeed).
			user_session.assert_icommand(['istream', 'write', copy_from_logical_path], 'STDOUT', input=new_content)
			user_session.assert_icommand(['icp', '-f', '-R', target_resource, copy_from_logical_path, copy_to_logical_path])

			# Assert that the copy occurred and the existing replicas have been updated appropriately.
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, target_resource))
			self.assertFalse(lib.replica_exists_on_resource(user_session, copy_to_logical_path, other_resource))

			self.assertEqual(
				str(0), lib.get_replica_status_for_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertEqual(str(1), lib.get_replica_status_for_resource(user_session, copy_to_logical_path, target_resource))

			self.assertEqual(
				original_content,
				user_session.assert_icommand(
					['istream', '-R', user_session.default_resource, 'read', copy_to_logical_path], 'STDOUT')[1].strip())

			self.assertEqual(
				new_content,
				user_session.assert_icommand(
					['istream', '-R', target_resource, 'read', copy_to_logical_path], 'STDOUT')[1].strip())

		finally:
			print(user_session.run_icommand(['ils', '-lr', copy_to_collection])[0].strip())
			print(user_session.run_icommand(['ils', '-lr', copy_from_collection])[0].strip())
			user_session.assert_icommand(['irm', '-f', copy_to_logical_path])
			user_session.assert_icommand(['irm', '-f', copy_from_logical_path])

	def test_success_to_remote_from_remote__issue_6497(self):
		self.successfully_overwrite_replica_on_target_resource_test_impl(copy_to='remote', copy_from='remote')

	def test_success_to_remote_from_local__issue_6497(self):
		self.successfully_overwrite_replica_on_target_resource_test_impl(copy_to='remote', copy_from='local')

	def test_success_to_local_from_remote__issue_6497(self):
		self.successfully_overwrite_replica_on_target_resource_test_impl(copy_to='local', copy_from='remote')

	def test_success_to_local_from_local__issue_6497(self):
		self.successfully_overwrite_replica_on_target_resource_test_impl(copy_to='local', copy_from='local')

	def fail_to_overwrite_replica_on_target_resource_test_impl(self, copy_to, copy_from):
		"""A test which fails to overwrite a replica with icp while targeting a resource which has no replica.

		Arguments:
		self - The test class.
		copy_to - The zone to copy to and overwrite a data object. Either "local" or "remote".
		copy_from - The zone from which a data object will be copied. Either "local" or "remote".
		"""
		# Use the session collection for the user in the appropriate "from" zone.
		user_session = self.local_user

		if copy_from == 'local':
			copy_from_collection = user_session.home_collection
		else:
			copy_from_collection = user_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)

		if copy_to == 'local':
			copy_to_collection = user_session.home_collection
			target_resource = self.local_target_resource
			other_resource = self.local_other_resource
		else:
			copy_to_collection = user_session.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)
			target_resource = self.remote_target_resource
			other_resource = self.remote_other_resource

		copy_to_object_name = 'copy_to_object'
		copy_from_object_name = 'copy_from_object'
		copy_to_logical_path = os.path.join(copy_to_collection, copy_to_object_name)
		copy_from_logical_path = os.path.join(copy_from_collection, copy_from_object_name)

		original_content = 'the color of infinity'
		new_content = 'inside an empty glass'

		try:
			# Make an object and replicate to some target resource...
			user_session.assert_icommand(['istream', 'write', copy_to_logical_path], 'STDOUT', input=original_content)
			user_session.assert_icommand(['irepl', '-R', target_resource, copy_to_logical_path])

			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, target_resource))
			self.assertFalse(lib.replica_exists_on_resource(user_session, copy_to_logical_path, other_resource))

			# Make a new object with different content and copy over the first object (the copy should fail).
			user_session.assert_icommand(['istream', 'write', copy_from_logical_path], 'STDOUT', input=new_content)
			user_session.assert_icommand(
				['icp', '-f', '-R', other_resource, copy_from_logical_path, copy_to_logical_path],
				'STDERR', '-1803000 HIERARCHY_ERROR')

			# Assert that no copy occurred and the existing replicas remain untouched.
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertTrue(lib.replica_exists_on_resource(user_session, copy_to_logical_path, target_resource))
			self.assertFalse(lib.replica_exists_on_resource(user_session, copy_to_logical_path, other_resource))

			self.assertEqual(
				str(1), lib.get_replica_status_for_resource(user_session, copy_to_logical_path, user_session.default_resource))
			self.assertEqual(str(1), lib.get_replica_status_for_resource(user_session, copy_to_logical_path, target_resource))

			self.assertEqual(
				original_content,
				user_session.assert_icommand(
					['istream', '-R', user_session.default_resource, 'read', copy_to_logical_path], 'STDOUT')[1].strip())

			self.assertEqual(
				original_content,
				user_session.assert_icommand(
					['istream', '-R', target_resource, 'read', copy_to_logical_path], 'STDOUT')[1].strip())

		finally:
			print(user_session.run_icommand(['ils', '-lr', copy_to_collection])[0].strip())
			print(user_session.run_icommand(['ils', '-lr', copy_from_collection])[0].strip())
			user_session.assert_icommand(['irm', '-f', copy_to_logical_path])
			user_session.assert_icommand(['irm', '-f', copy_from_logical_path])

	def test_failure_to_remote_from_remote__issue_6497(self):
		self.fail_to_overwrite_replica_on_target_resource_test_impl(copy_to='remote', copy_from='remote')

	def test_failure_to_remote_from_local__issue_6497(self):
		self.fail_to_overwrite_replica_on_target_resource_test_impl(copy_to='remote', copy_from='local')

	def test_failure_to_local_from_remote__issue_6497(self):
		self.fail_to_overwrite_replica_on_target_resource_test_impl(copy_to='local', copy_from='remote')

	def test_failure_to_local_from_local__issue_6497(self):
		self.fail_to_overwrite_replica_on_target_resource_test_impl(copy_to='local', copy_from='local')


class test_irepl_all_permission_levels__issue_7444_7465(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		# Create a session as the administrator for the remote zone so we can do things in the remote zone.
		self.remote_admin = session.make_session_for_existing_user(
			test.settings.PREEXISTING_ADMIN_USERNAME,
			test.settings.PREEXISTING_ADMIN_PASSWORD,
			test.settings.FEDERATION.REMOTE_HOST,
			test.settings.FEDERATION.REMOTE_ZONE)

		# Create two users in the local zone and accompanying users in the remote zone.
		local_user_name0 = 'smeagol'
		local_user_name1 = 'bilbo'
		self.user0 = session.mkuser_and_return_session(
			'rodsuser', local_user_name0, 'spass', lib.get_hostname())
		self.user1 = session.mkuser_and_return_session(
			'rodsuser', local_user_name1, 'bpass', lib.get_hostname())

		# Create a user in the remote zone for each local zone's test users. Don't give the user a password.
		self.local_user0_remote_name = '#'.join([self.user0.username, self.user0.zone_name])
		self.local_user1_remote_name = '#'.join([self.user1.username, self.user1.zone_name])
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', self.local_user0_remote_name, 'rodsuser'])
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', self.local_user1_remote_name, 'rodsuser'])

		# Give other user ownership of the session collection so we can focus on object permissions.
		self.user0.assert_icommand(
			['ichmod', 'own', self.local_user1_remote_name, self.user0.remote_home_collection(test.settings.FEDERATION.REMOTE_ZONE)])

		# Create a couple of resources in the local and remote zone for testing.
		self.target_resource = 'remote_target_resource'
		self.other_resource = 'remote_other_resource'
		lib.create_ufs_resource(
			self.remote_admin, self.target_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)
		lib.create_ufs_resource(
			self.remote_admin, self.other_resource, hostname=test.settings.FEDERATION.REMOTE_HOST)

	@classmethod
	def tearDownClass(self):
		# Clean up remote users, sessions, and resources.
		self.remote_admin.assert_icommand(['iadmin', 'rmuser', self.local_user0_remote_name])
		self.remote_admin.assert_icommand(['iadmin', 'rmuser', self.local_user1_remote_name])
		lib.remove_resource(self.remote_admin, self.target_resource)
		lib.remove_resource(self.remote_admin, self.other_resource)
		self.remote_admin.__exit__()

		# Clean up local users, sessions, and resources.
		self.user0.__exit__()
		self.user1.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.assert_icommand(['iadmin', 'rmuser', self.user0.username])
			admin_session.assert_icommand(['iadmin', 'rmuser', self.user1.username])

	def test_permissions_that_do_not_allow_user_to_see_object_results_in_no_replication_and_an_error(self):
		remote_zone = test.settings.FEDERATION.REMOTE_ZONE
		logical_path = os.path.join(self.user0.remote_home_collection(remote_zone), 'this_object_is_invisible')
		permissions = [None, 'null', 'read_metadata']

		for permission in permissions:
			with self.subTest(str(permission)):
				try:
					# Create a data object and make sure it is good.
					self.user0.assert_icommand(['itouch', '-R', self.target_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))

					if permission is not None:
						self.user0.assert_icommand(['ichmod', permission, self.local_user1_remote_name, logical_path])

					# Try to replicate the data object and fail because user1 cannot even see the data object.
					self.user1.assert_icommand(
						['irepl', '-R', self.other_resource, logical_path], 'STDERR', 'does not exist')
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertFalse(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Now replicate the data object and set it to stale so that it is possible to be updated.
					self.user0.assert_icommand(['irepl', '-R', self.other_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))
					lib.set_replica_status(self.remote_admin, logical_path, 1, 0)
					self.assertEqual(
						str(0), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Try to update the stale replicas and ensure that it fails with an error.
					self.user1.assert_icommand(['irepl', '-a', logical_path], 'STDERR', 'does not exist')
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(0), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

				finally:
					# In the case where this test does not pass (i.e. REGRESSION) it is possible for the replicas to be
					# stuck in the intermediate or write-locked status. We set the status at the end here to ensure
					# that the object can be removed.
					self.remote_admin.assert_icommand(['ils', '-L', os.path.dirname(logical_path)], 'STDOUT') # debug
					for replica_number in range(2):
						self.remote_admin.run_icommand([
							'iadmin', 'modrepl',
							'logical_path', logical_path,
							'replica_number', str(replica_number),
							'DATA_REPL_STATUS', str(0)
						])
					self.user0.assert_icommand(['irm', '-f', logical_path])

	def test_insufficient_permissions_results_in_no_replication_and_an_error(self):
		remote_zone = test.settings.FEDERATION.REMOTE_ZONE
		logical_path = os.path.join(self.user0.remote_home_collection(remote_zone), 'this_object_will_not_be_replicated')
		permissions = ['read_object', 'create_metadata', 'modify_metadata', 'delete_metadata', 'create_object']

		for permission in permissions:
			with self.subTest(permission):
				try:
					# Create a data object and make sure it is good.
					self.user0.assert_icommand(['itouch', '-R', self.target_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))

					self.user0.assert_icommand(['ichmod', permission, self.local_user1_remote_name, logical_path])

					# Try to replicate the data object and ensure that it fails with an error.
					self.user1.assert_icommand(
						['irepl', '-R', self.other_resource, logical_path], 'STDERR', 'SYS_USER_NO_PERMISSION')
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertFalse(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Now replicate the data object and set it to stale so that it is possible to be updated.
					self.user0.assert_icommand(['irepl', '-R', self.other_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))
					lib.set_replica_status(self.remote_admin, logical_path, 1, 0)
					self.assertEqual(
						str(0), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Try to update the stale replicas and ensure that it fails with an error.
					self.user1.assert_icommand(['irepl', '-a', logical_path], 'STDERR', 'SYS_USER_NO_PERMISSION')
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(0), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

				finally:
					# In the case where this test does not pass (i.e. REGRESSION) it is possible for the replicas to be
					# stuck in the intermediate or write-locked status. We set the status at the end here to ensure
					# that the object can be removed.
					self.remote_admin.assert_icommand(['ils', '-L', os.path.dirname(logical_path)], 'STDOUT') # debug
					for replica_number in range(2):
						self.remote_admin.run_icommand([
							'iadmin', 'modrepl',
							'logical_path', logical_path,
							'replica_number', str(replica_number),
							'DATA_REPL_STATUS', str(0)
						])
					self.user0.assert_icommand(['irm', '-f', logical_path])

	def test_sufficient_permissions_results_in_replication_and_no_error(self):
		remote_zone = test.settings.FEDERATION.REMOTE_ZONE
		logical_path = os.path.join(self.user0.remote_home_collection(remote_zone), 'this_object_will_be_replicated')
		permissions = ['modify_object', 'delete_object', 'own']

		for permission in permissions:
			with self.subTest(permission):
				try:
					# Create a data object and make sure it is good.
					self.user0.assert_icommand(['itouch', '-R', self.target_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))

					self.user0.assert_icommand(['ichmod', permission, self.local_user1_remote_name, logical_path])

					# Try to replicate the data object and ensure that it completes successfully.
					self.user1.assert_icommand(['irepl', '-R', self.other_resource, logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Set a replica to stale so that it is possible to be updated.
					lib.set_replica_status(self.remote_admin, logical_path, 1, 0)
					self.assertEqual(
						str(0), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

					# Try to update the stale replicas and ensure that it completes successfully.
					self.user1.assert_icommand(['irepl', '-a', logical_path])
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.target_resource, remote_zone))
					self.assertTrue(lib.replica_exists_on_resource(self.user0, logical_path, self.other_resource, remote_zone))
					self.assertEqual(
						str(1), lib.get_replica_status_for_resource(self.user0, logical_path, self.other_resource, remote_zone))

				finally:
					# In the case where this test does not pass (i.e. REGRESSION) it is possible for the replicas to be
					# stuck in the intermediate or write-locked status. We set the status at the end here to ensure
					# that the object can be removed.
					self.remote_admin.assert_icommand(['ils', '-L', os.path.dirname(logical_path)], 'STDOUT') # debug
					for replica_number in range(2):
						self.remote_admin.run_icommand([
							'iadmin', 'modrepl',
							'logical_path', logical_path,
							'replica_number', str(replica_number),
							'DATA_REPL_STATUS', str(0)
						])
					self.user0.assert_icommand(['irm', '-f', logical_path])


class test_iget_data_in_remote_zone(unittest.TestCase):
	@classmethod
	def setUpClass(self):
		# Create a session as the administrator for the remote zone so we can do things in the remote zone.
		self.remote_admin = session.make_session_for_existing_user(
			test.settings.PREEXISTING_ADMIN_USERNAME,
			test.settings.PREEXISTING_ADMIN_PASSWORD,
			test.settings.FEDERATION.REMOTE_HOST,
			test.settings.FEDERATION.REMOTE_ZONE)

		# Create two users in the local zone and accompanying users in the remote zone.
		local_user_name0 = 'smeagol'
		local_user_name1 = 'bilbo'
		self.user0 = session.mkuser_and_return_session(
			'rodsuser', local_user_name0, 'spass', lib.get_hostname())
		self.user1 = session.mkuser_and_return_session(
			'rodsuser', local_user_name1, 'bpass', lib.get_hostname())

		# Create a user in the remote zone for each local zone's test users. Don't give the user a password.
		self.local_user0_remote_name = '#'.join([self.user0.username, self.user0.zone_name])
		self.local_user1_remote_name = '#'.join([self.user1.username, self.user1.zone_name])
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', self.local_user0_remote_name, 'rodsuser'])
		self.remote_admin.assert_icommand(['iadmin', 'mkuser', self.local_user1_remote_name, 'rodsuser'])

	@classmethod
	def tearDownClass(self):
		# Clean up remote users and sessions.
		self.remote_admin.run_icommand(['iadmin', 'rmuser', self.local_user0_remote_name])
		self.remote_admin.run_icommand(['iadmin', 'rmuser', self.local_user1_remote_name])
		self.remote_admin.__exit__()

		# Clean up local users and sessions.
		self.user0.__exit__()
		self.user1.__exit__()
		with session.make_session_for_existing_admin() as admin_session:
			admin_session.run_icommand(['iadmin', 'rmuser', self.user0.username])
			admin_session.run_icommand(['iadmin', 'rmuser', self.user1.username])

	def test_iget_object_in_zoneB_as_user_in_zoneA_that_has_no_remote_user_in_zoneB_fails_correctly__issue_6421(self):
		remote_zone = test.settings.FEDERATION.REMOTE_ZONE
		logical_path = os.path.join(self.user0.remote_home_collection(remote_zone), "get_this_object")

		try:
			# Remove the user1 remote user so that it does not exist.
			self.remote_admin.assert_icommand(['iadmin', 'rmuser', self.local_user1_remote_name])

			# Create a data object in the remote zone in the remote user0's home collection.
			content = "we hates it"
			self.user0.assert_icommand(["istream", "write", logical_path], input=content)
			self.user0.assert_icommand(["istream", "read", logical_path], "STDOUT", content)

			# Try to get the data as user1 even though there is no remote user for user1. This should fail.
			self.user1.assert_icommand(["iget", logical_path], "STDERR", "-317000 USER_INPUT_PATH_ERR")

		finally:
			self.remote_admin.run_icommand(['iadmin', 'mkuser', self.local_user1_remote_name, 'rodsuser'])
			self.user0.run_icommand(["irm", "-f", logical_path])

	def test_iget_object_in_zoneB_as_user_in_zoneA_that_has_no_permissions_fails_correctly__issue_6421(self):
		remote_zone = test.settings.FEDERATION.REMOTE_ZONE
		parent_collection = self.user0.remote_home_collection(remote_zone)
		logical_path = os.path.join(parent_collection, "get_this_object")

		try:
			# Create a data object in the remote zone in the remote user0's home collection.
			content = "we hates it"
			self.user0.assert_icommand(["istream", "write", logical_path], input=content)
			self.user0.assert_icommand(["istream", "read", logical_path], "STDOUT", content)

			# Try to get the data as user1 even though the remote user1 has no permissions. This should fail.
			self.user1.assert_icommand(["iget", logical_path], "STDERR", "-317000 USER_INPUT_PATH_ERR")

			# Give the other user read permission on the parent collection.
			self.user0.assert_icommand(["ichmod", "read_object", self.local_user1_remote_name, parent_collection])

			# Try to get the data as user1 even though the remote user1 only has permissions on the parent collection.
			# This should fail, too.
			self.user1.assert_icommand(["iget", logical_path], "STDERR", "-317000 USER_INPUT_PATH_ERR")

		finally:
			self.user0.run_icommand(["irm", "-f", logical_path])


class Test_GenQuery2_IQuery(SessionsMixin, unittest.TestCase):

	# This test suite expects tempZone to contain the following users:
	#
	#   - rods#tempZone
	#   - zonehopper#tempZone
	#   - zonehopper#otherZone
	#
	# otherZone must contain the following users:
	#
	#   - rods#otherZone
	#
	# The test suite must be launched from a server in otherZone. That means tempZone
	# is identified as the remote federated zone.
	#
	# Just before the tests are run, the base class will create two additional users
	# in otherZone. The following users will appear:
	#
	#   - admin#otherZone
	#   - zonehopper#otherZone

	def setUp(self):
		super(Test_GenQuery2_IQuery, self).setUp()

		# session.make_sessions_mixin() creates admins and users that connect to the host
		# identified by lib.get_hostname().
		#
		# For this particular set of tests, that means these users connect to the host where
		# "otherZone" runs.
		self.local_admin = self.admin_sessions[0] # admin#otherZone
		self.local_user = self.user_sessions[0]   # zonehopper#otherZone

		# Create session for zonehopper#tempZone. The session will be connected to tempZone.
		password = test.settings.FEDERATION.RODSUSER_NAME_PASSWORD_LIST[0][1]
		host = test.settings.FEDERATION.REMOTE_HOST
		zone = test.settings.FEDERATION.REMOTE_ZONE
		self.remote_user = session.make_session_for_existing_user(self.local_user.username, password, host, zone)

	def tearDown(self):
		self.remote_user.__exit__()
		super(Test_GenQuery2_IQuery, self).tearDown()

	def test_iquery_correctly_honors_permissions_when_users_share_the_same_username_but_different_zone_names__issue_7570(self):
		import json

		remote_zone = test.settings.FEDERATION.REMOTE_ZONE

		# Show the local user can find their remote home collection using iquery.
		local_user_remote_home_collection = self.local_user.remote_home_collection(remote_zone)
		query = f"select COLL_NAME where COLL_NAME = '{local_user_remote_home_collection}'"
		self.local_user.assert_icommand(['iquery', '-z', remote_zone, query], 'STDOUT', [local_user_remote_home_collection])

		# Show the local user cannot find the remote home collection of the remote user using iquery.
		query = f"select COLL_NAME where COLL_NAME = '{self.remote_user.home_collection}'"
		self.local_user.assert_icommand(['iquery', '-z', remote_zone, query], 'STDOUT', ['[]'])

		# Give the local user read permission on the remote user's remote home collection and show that
		# iquery now returns a non-empty resultset.
		self.remote_user.assert_icommand(['ichmod', 'read_object', self.local_user.qualified_username, self.remote_user.home_collection])
		self.local_user.assert_icommand(['iquery', '-z', remote_zone, query], 'STDOUT', [self.remote_user.home_collection])

		#
		# Demonstrate the same thing using data objects.
		#

		# Create a data object in the remote user's home collection.
		data_object = f'{self.remote_user.home_collection}/issue_7570.txt'
		self.remote_user.assert_icommand(['itouch', data_object])

		# Give the local user permission to read the contents of the remote user's remote home collection.
		# This allows the local user to list the contents of the remote user's remote home collection.
		self.remote_user.assert_icommand(['ichmod', 'read_object', self.local_user.qualified_username, self.remote_user.home_collection])

		# Show the remote user can find the data object using iquery.
		remote_coll_name = self.remote_user.home_collection
		remote_data_name = os.path.basename(data_object)
		query = f"select COLL_NAME, DATA_NAME where COLL_NAME = '{remote_coll_name}' and DATA_NAME = '{remote_data_name}'"
		expected_output = [json.dumps([[remote_coll_name, remote_data_name]], separators=(',', ':'))]
		self.remote_user.assert_icommand(['iquery', query], 'STDOUT', expected_output)

		# Show the local user cannot find the remote data object of the remote user using iquery.
		# This proves that iquery understands the permission model for data objects even in federated environments.
		query = f"select COLL_NAME, DATA_NAME where COLL_NAME = '{remote_coll_name}' and DATA_NAME = '{remote_data_name}'"
		self.local_user.assert_icommand(['iquery', '-z', remote_zone, query], 'STDOUT', ['[]'])

		# Give the local user read permission on the remote user's data object and show that iquery
		# now returns a non-empty resultset.
		self.remote_user.assert_icommand(['ichmod', 'read_object', self.local_user.qualified_username, data_object])
		self.local_user.assert_icommand(['iquery', '-z', remote_zone, query], 'STDOUT', expected_output)
