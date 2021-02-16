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
import testtools

from oslo_log import log as logging
from tempest.api.compute import base as compute_base
from tempest.common import utils
from tempest import config
from tempest import exceptions
from tempest.lib.common import api_version_utils
from tempest.lib import decorators

from barbican_tempest_plugin.tests.scenario import barbican_manager

CONF = config.CONF
LOG = logging.getLogger(__name__)


class ImageSigningTest(barbican_manager.BarbicanScenarioTest):
    min_microversion = '2.1'

    @classmethod
    def resource_setup(cls):
        super(ImageSigningTest, cls).resource_setup()
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.compute.min_microversion))

    @decorators.idempotent_id('4343df3c-5553-40ea-8705-0cce73b297a9')
    @utils.services('compute', 'image')
    def test_signed_image_upload_and_boot(self):
        """Test that Nova boots a signed image.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Boot the signed image
            * Confirm the instance changes state to Active
        """
        img_uuid = self.sign_and_upload_image()

        LOG.debug("Booting server with signed image %s", img_uuid)
        instance = self.create_server(name='signed_img_server',
                                      image_id=img_uuid,
                                      wait_until='ACTIVE')
        self.servers_client.delete_server(instance['id'])

    @decorators.idempotent_id('74f022d6-a6ef-4458-96b7-541deadacf99')
    @utils.services('compute', 'image')
    @testtools.skipUnless(CONF.image_signature_verification.enforced,
                          "Image signature verification is not enforced")
    def test_signed_image_upload_boot_failure(self):
        """Test that Nova refuses to boot an incorrectly signed image.

        If the create_server call succeeds instead of throwing an
        exception, it is likely that signature verification is not
        turned on.  To turn on signature verification, set
        verify_glance_signatures=True in the nova configuration
        file under the [glance] section.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Modify the signature to be incorrect
            * Attempt to boot the incorrectly signed image
            * Confirm an exception is thrown
        """

        img_uuid = self.sign_and_upload_image()

        LOG.debug("Modifying image signature to be incorrect")
        patch = [dict(replace='/img_signature', value='fake_signature')]
        self.image_client.update_image(image_id=img_uuid, patch=patch)

        self.assertRaisesRegex(exceptions.BuildErrorException,
                               "Signature verification for the image failed",
                               self.create_server,
                               image_id=img_uuid)


class ImageSigningSnapshotTest(barbican_manager.BarbicanScenarioTest,
                               compute_base.BaseV2ComputeTest):

    @classmethod
    def setup_clients(cls):
        super(ImageSigningSnapshotTest, cls).setup_clients()
        cls.client = cls.servers_client

    @decorators.idempotent_id('f0603dfd-8b2c-44e2-8b0f-d65c87aab257')
    @utils.services('compute', 'image')
    def test_signed_image_upload_boot_snapshot(self):
        """Test that Glance can snapshot an instance using a signed image.

        Verify that a snapshot can be taken of an instance booted from a signed
        image and that the resulting snapshot image has had all image signature
        properties dropped from the original image.

        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Boot the signed image
            * Confirm the instance changes state to Active
            * Snapshot the running instance
            * Uploading the snapshot and confirm the state moves to ACTIVE
        """
        img_uuid = self.sign_and_upload_image()
        instance = self.create_server(name='signed_img_server_to_snapshot',
                                      image_id=img_uuid,
                                      wait_until='ACTIVE')

        # Snapshot the instance, wait until the snapshot is active
        image = self.create_image_from_server(instance['id'],
                                              wait_until='ACTIVE')

        # Ensure all img_signature image props have been dropped
        signature_props = ['img_signature_hash_method',
                           'img_signature',
                           'img_signature_key_type',
                           'img_signature_certificate_uuid']
        img_meta = self.compute_images_client.list_image_metadata(image['id'])
        self.assertFalse(any(x in img_meta for x in signature_props))

        self.servers_client.delete_server(instance['id'])
