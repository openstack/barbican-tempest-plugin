# Copyright (c) 2017 Johns Hopkins University Applied Physics Laboratory
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging
from tempest.common import utils
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib import decorators

from barbican_tempest_plugin.tests.scenario import barbican_manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class EphemeralStorageEncryptionTest(barbican_manager.BarbicanScenarioTest):
    min_microversion = '2.1'

    """The test suite for encrypted ephemeral storage

    This test verifies the functionality of encrypted ephemeral storage.
    This test performs the following:
        * Creates an image in Glance
        * Boots an instance from the image
        * Writes to a new file in the instance
    """

    @classmethod
    def skip_checks(cls):
        super(EphemeralStorageEncryptionTest, cls).skip_checks()
        if not CONF.ephemeral_storage_encryption.enabled:
            raise cls.skipException(
                'Ephemeral storage encryption is not supported')
        if not CONF.auth.create_isolated_networks:
            # FIXME(redorobt): remove this skip when system-scope admin
            # issue is fixed.
            raise cls.skipException(
                'Ephemeral storage encryption requires isolated networks')

    @classmethod
    def resource_setup(cls):
        super(EphemeralStorageEncryptionTest, cls).resource_setup()
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.compute.min_microversion))

    @decorators.idempotent_id('afe720b9-8b35-4a3c-8ff3-15841c2d3148')
    @utils.services('compute', 'image')
    def test_encrypted_ephemeral_lvm_storage(self):
        test_string = 'Once upon a time ...'
        client_test_path = '/tmp/ephemeral_disk_encryption_test'
        img_uuid = self.sign_and_upload_image()
        keypair = self.create_keypair()
        security_group = self._create_security_group()
        instance = self.create_server(
            name='signed_img_server',
            image_id=img_uuid,
            key_name=keypair['name'],
            security_groups=[{'name': security_group['name']}],
            wait_until='ACTIVE')
        instance_ip = self.get_server_ip(instance)
        ssh_client = self.get_remote_client(
            instance_ip,
            private_key=keypair['private_key'])
        ssh_client.exec_command('echo "%s" > %s' % (test_string,
                                                    client_test_path))
        test_output = ssh_client.exec_command('cat %s' % client_test_path)
        self.assertEqual(str(test_string), str(test_output.rstrip()))
