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
from tempest.common import waiters
from tempest import config
from tempest import exceptions
from tempest.lib.common import api_version_utils
from tempest.lib import decorators

from barbican_tempest_plugin.tests.scenario import barbican_manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class CertificateValidationTest(barbican_manager.BarbicanScenarioTest):
    min_microversion = '2.63'
    max_microversion = 'latest'

    @classmethod
    def resource_setup(cls):
        super(CertificateValidationTest, cls).resource_setup()
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.compute.min_microversion))

    @classmethod
    def skip_checks(cls):
        super(CertificateValidationTest, cls).skip_checks()
        api_version_utils.check_skip_with_microversion(
            cls.min_microversion,
            cls.max_microversion,
            CONF.compute.min_microversion,
            CONF.compute.max_microversion)
        if not CONF.auth.create_isolated_networks:
            # FIXME(redorobt): remove this skip when system-scope admin
            # issue is fixed.
            raise cls.skipException(
                'Certificate Validation tests require isolated networks')

    @decorators.idempotent_id('b41bc663-5662-4b1e-b8f1-27b2876f16a6')
    @utils.services('compute', 'image')
    def test_signed_image_upload_and_boot(self):
        """Test that Nova boots a signed image.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Boot the signed image with a valid trusted image certificate ID
            * Confirm the instance changes state to Active
        """
        img_uuid = self.sign_and_upload_image()

        LOG.debug("Booting server with self-signed image %s and certificate "
                  "ID %s", img_uuid, self.signing_cert_uuid)
        instance = self.create_server(name='signed_img_server',
                                      image_id=img_uuid,
                                      wait_until='ACTIVE',
                                      trusted_image_certificates=[
                                          self.signing_cert_uuid])
        self.servers_client.delete_server(instance['id'])

    @decorators.idempotent_id('6d354881-35a6-4568-94b8-2204bbf67b29')
    @utils.services('compute', 'image')
    def test_signed_image_invalid_cert_boot_failure(self):
        """Test that Nova refuses to boot an unvalidated signed image.

        If the create_server call succeeds instead of throwing an
        exception, it is likely that certificate validation is not
        turned on.  To turn on certificate validation, set
        enable_certificate_validation=True in the nova configuration
        file under the [glance] section.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Attempt to boot the signed image with an invalid trusted
              image certificate ID
            * Confirm an exception is thrown
        """
        img_uuid = self.sign_and_upload_image()

        LOG.debug("Booting server with self-signed image %s and invalid "
                  "certificate ID %s", img_uuid, self.bad_cert_uuid)
        self.assertRaisesRegex(exceptions.BuildErrorException,
                               "Certificate chain building failed",
                               self.create_server,
                               image_id=img_uuid,
                               trusted_image_certificates=[self.bad_cert_uuid])

    @decorators.idempotent_id('aed5254d-1e7a-46b6-8cb0-ef5fd798671a')
    @utils.services('compute', 'image')
    def test_signed_image_upload_and_hard_reboot(self):
        """Test that Nova boots a signed image with certs after a hard reboot.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Boot the signed image with a valid trusted image certificate ID
            * Reboot the signed image
            * Confirm the instance changes state to Active
        """
        img_uuid = self.sign_and_upload_image()

        LOG.debug("Booting server with self-signed image %s and certificate "
                  "ID %s", img_uuid, self.signing_cert_uuid)
        instance = self.create_server(name='server_to_reboot',
                                      image_id=img_uuid,
                                      wait_until='ACTIVE',
                                      trusted_image_certificates=[
                                          self.signing_cert_uuid])

        LOG.debug("Hard rebooting server with self-signed image %s and "
                  "certificate ID %s", img_uuid, self.signing_cert_uuid)
        self.servers_client.reboot_server(instance['id'], type='HARD')
        waiters.wait_for_server_status(self.servers_client, instance['id'],
                                       'ACTIVE')
        self.servers_client.delete_server(instance['id'])

    @decorators.idempotent_id('f9c6de51-b027-476f-a6e3-847bb39cfa02')
    @utils.services('compute', 'image')
    def test_signed_image_upload_and_server_rebuild(self):
        """Test that Nova boots a signed image with certs after a rebuild.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Boot the server with the first signed image
            * Build a second signed image
            * Rebuild the server with the second signed image with a valid
              trusted image certificate ID
            * Confirm the instance changes state to Active
        """
        img_uuid_create = self.sign_and_upload_image()

        LOG.debug("Booting server with self-signed image %s and certificate "
                  "ID %s", img_uuid_create, self.signing_cert_uuid)
        instance = self.create_server(name='server_to_rebuild',
                                      image_id=img_uuid_create,
                                      wait_until='ACTIVE')

        img_uuid_rebuild = self.sign_and_upload_image()
        LOG.debug("Rebuild server with self-signed image %s and certificate "
                  "ID %s", img_uuid_rebuild, self.signing_cert_uuid)
        rebuild_kwargs = {
            'trusted_image_certificates': [self.signing_cert_uuid],
        }
        self.rebuild_server(instance['id'],
                            img_uuid_rebuild,
                            rebuild_kwargs=rebuild_kwargs)
        self.servers_client.delete_server(instance['id'])
