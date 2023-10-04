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
from tempest.api.image import base

from tempest.common import utils
from tempest.common import waiters

from tempest import config
from tempest import exceptions
from tempest.lib.common import api_version_utils
from tempest.lib import decorators
from tempest.scenario import manager as tempest_manager

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


class ImageSigningVolumeTest(barbican_manager.BarbicanScenarioTest,
                             tempest_manager.EncryptionScenarioTest,
                             compute_base.BaseV2ComputeTest,
                             base.BaseV2ImageTest):
    """Tests with signed volumes

    The cinder image signature feature is on by default.
    The set of operation is:
        * Create signed volume or create encrypted signed volume
        * Create and upload signed image
        * Create instance
        * Attach signed volume to instance
    """

    min_microversion = '2.1'

    @classmethod
    def skip_checks(cls):
        super(ImageSigningVolumeTest, cls).skip_checks()
        if not CONF.compute_feature_enabled.attach_encrypted_volume:
            raise cls.skipException("Attach encrypted volumes not supported")
        if not CONF.volume_feature_enabled.extend_attached_volume:
            raise cls.skipException("Extend attached volume not supported")
        if not CONF.volume_feature_enabled.extend_attached_encrypted_volume:
            raise cls.skipException("Extend attached"
                                    "encrypted volume not supported")
        if not CONF.service_available.nova:
            raise cls.skipException("Nova service not available")

    def _create_encrypted_signed_volume(self,
                                        encryption_provider,
                                        volume_type,
                                        key_size=256,
                                        cipher='aes-xts-plain64',
                                        control_location='front-end',
                                        imageRef=None):

        """Create an encrypted signed volume"""
        volume_type = self.create_volume_type(name=volume_type)
        self.create_encryption_type(type_id=volume_type['id'],
                                    provider=encryption_provider,
                                    key_size=key_size,
                                    cipher=cipher,
                                    control_location=control_location)
        return self.create_volume(imageRef=imageRef,
                                  volume_type=volume_type['name'])

    def _volume_create(self, volume_type=None, img_uuid=str):
        """Create extended signed volume or signed volume"""

        # Create encrypted extended signed volume
        if volume_type == 'encrypted':
            volume = self._create_encrypted_signed_volume('luks',
                                                          volume_type='luks',
                                                          imageRef=img_uuid)
            LOG.info("Create encrypted volume%s", volume)
            waiters.wait_for_volume_resource_status(
                self.volumes_client, volume['id'], 'available')
            self.assertEqual(volume['encrypted'], True)
            extend_size = volume['size'] * 2
            self.volumes_client.extend_volume(volume_id=volume['id'],
                                              new_size=extend_size)
            LOG.info("Extend volume %s", volume)
            waiters.wait_for_volume_resource_status(
                self.volumes_client,
                volume['id'], 'available')
            resized_volume = self.volumes_client.show_volume(
                volume['id'])['volume']
            self.assertEqual(extend_size, resized_volume['size'])
            return resized_volume

        # Create signed volume
        if img_uuid:
            volume = self.create_volume(imageRef=img_uuid)
            waiters.wait_for_volume_resource_status(
                self.volumes_client, volume['id'], 'available')
            LOG.info("Create volume from signed image %s", volume)
            return volume

    def _create_instance_attach_volume(self, img_uuid, resized_volume):
        """Create instance and attach extended signed volume

        The method follows these steps:
            * Create instance from signed image
            * Confirm the instance changes state to Active
            * Attach encrypted or signed volume to instance
            * Detach volume from instance
            * Delete instance
        """
        # Create instance from signed image
        instance = self.create_server(name='signed_img_server',
                                      image_id=img_uuid,
                                      wait_until='ACTIVE')
        LOG.info("Create instance with signed image %s", instance)
        instance_id = instance['id']

        # Attach volume to instance
        attachment = self.attach_volume(instance, resized_volume)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                attachment['volumeId'],
                                                'in-use')
        LOG.info("Attach volume %s to instance %s", resized_volume, instance)
        self.assertEqual(img_uuid, instance['image']['id'])

        instance_observed = \
            self.servers_client.show_server(instance_id)['server']
        self.assertEqual(
            resized_volume['id'],
            instance_observed['os-extended-volumes:volumes_attached'][0]['id'])

        self.delete_server(instance_observed['id'])

    @decorators.idempotent_id('72ca044d-39a4-4966-b302-f53a446d3e29')
    @decorators.attr(type='slow')
    @utils.services('compute', 'image', 'volume')
    def test_extend_encrypted_signed_volume_attach_to_instance(self):
        """Create volume from signed image, extend volume

        and attach volume to instance.
        Verify that volume can be created from signed image and had
        image signature properties.
        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Create encrypted signed volume from image and resize volume
            * Create instance from signed image
            * Confirm the instance changes state to Active
            * Attach encrypted signed volume to instance
            * Detach volume from instance
            * Delete instance
        """
        # Create an encrypted volume and extend volume
        img_uuid = self.sign_and_upload_image()
        resized_volume = self._volume_create(volume_type='encrypted',
                                             img_uuid=img_uuid)
        observed_image = self.images_client.show_image(img_uuid)
        self.assertEqual(
            resized_volume['volume_image_metadata']['signature_verified'],
            'True')
        self.assertEqual(
            resized_volume['volume_image_metadata']
            ['img_signature_certificate_uuid'],
            observed_image['img_signature_certificate_uuid'])
        self._create_instance_attach_volume(img_uuid, resized_volume)

    @decorators.idempotent_id('9f28ce2e-362e-46ec-bf56-aebce9cc49fb')
    @decorators.attr(type='slow')
    @utils.services('compute', 'image', 'volume')
    def test_signed_volume_attach_to_instance(self):
        """Create volume from signed image and attach volume to instance

        Verify that volume can be created from signed image and had
        image signature properties.
        The test follows these steps:
            * Create an asymmetric keypair
            * Sign an image file with the private key
            * Create a certificate with the public key
            * Store the certificate in Barbican
            * Store the signed image in Glance
            * Create signed volume from image
            * Create instance from signed image
            * Confirm the instance changes state to Active
            * Attach signed volume to instance
            * Detach volume from instance
            * Delete instance
        """

        # Create image
        img_uuid = self.sign_and_upload_image()

        # Create volume from signed image
        volume = self._volume_create(img_uuid=img_uuid)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')
        observed_image = self.images_client.show_image(img_uuid)
        self.assertEqual(
            volume['volume_image_metadata']['signature_verified'],
            'True')
        self.assertEqual(
            volume['volume_image_metadata']['img_signature_certificate_uuid'],
            observed_image['img_signature_certificate_uuid'])
        self._create_instance_attach_volume(img_uuid, volume)
