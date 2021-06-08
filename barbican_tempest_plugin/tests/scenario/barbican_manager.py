# Copyright 2017 Johns Hopkins Applied Physics Lab
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import base64
from datetime import datetime
from datetime import timedelta
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from oslo_log import log as logging
from tempest.api.compute import api_microversion_fixture
from tempest import config

from barbican_tempest_plugin.tests.scenario import manager as mgr

CONF = config.CONF
LOG = logging.getLogger(__name__)
COMPUTE_MICROVERSION = CONF.compute.min_microversion


class BarbicanScenarioTest(mgr.ScenarioTest):

    api_microversion_header_name = 'X-OpenStack-Nova-API-Version'
    credentials = ('primary', 'admin')

    def get_headers(self):
        headers = super(BarbicanScenarioTest, self).get_headers()
        if COMPUTE_MICROVERSION:
            headers[self.api_microversion_header_name] = COMPUTE_MICROVERSION
        return headers

    def setUp(self):
        super(BarbicanScenarioTest, self).setUp()
        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            self.request_microversion))
        self.img_file = CONF.scenario.img_file
        if not os.path.exists(self.img_file):
            # TODO(kopecmartin): replace LOG.warning for rasing
            # InvalidConfiguration exception after tempest 25.0.0 is
            # released - there will be one release which accepts both
            # behaviors in order to avoid many failures across CIs and etc.
            LOG.warning(
                'Starting Tempest 25.0.0 release, CONF.scenario.img_file need '
                'a full path for the image. CONF.scenario.img_dir was '
                'deprecated and will be removed in the next release. Till '
                'Tempest 25.0.0, old behavior is maintained and keep working '
                'but starting Tempest 26.0.0, you need to specify the full '
                'path in CONF.scenario.img_file config option.')
            self.img_file = os.path.join(CONF.scenario.img_dir, self.img_file)

        self.private_key = rsa.generate_private_key(public_exponent=65537,
                                                    key_size=3072,
                                                    backend=default_backend())
        self.signing_certificate = self._create_self_signed_certificate(
            self.private_key,
            u"Test Certificate"
        )
        self.signing_cert_uuid = self._store_cert(
            self.signing_certificate
        )
        self.bad_signing_certificate = self._create_self_signed_certificate(
            self.private_key,
            u"Bad Certificate"
        )
        self.bad_cert_uuid = self._store_cert(
            self.bad_signing_certificate
        )

    @classmethod
    def skip_checks(cls):
        super(BarbicanScenarioTest, cls).skip_checks()
        if not CONF.service_available.barbican:
            raise cls.skipException('Barbican is not enabled.')

    @classmethod
    def setup_clients(cls):
        super(BarbicanScenarioTest, cls).setup_clients()

        os = getattr(cls, 'os_%s' % cls.credentials[0])
        os_adm = getattr(cls, 'os_%s' % cls.credentials[1])
        cls.consumer_client = os.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.container_client = os.secret_v1.ContainerClient(
            service='key-manager'
        )
        cls.order_client = os.secret_v1.OrderClient(service='key-manager')
        cls.secret_client = os.secret_v1.SecretClient(service='key-manager')
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )

        if CONF.compute_feature_enabled.attach_encrypted_volume:
            cls.admin_volume_types_client =\
                os_adm.volume_types_v2_client
            cls.admin_encryption_types_client =\
                os_adm.encryption_types_v2_client

    def _get_uuid(self, href):
        return href.split('/')[-1]

    def _create_self_signed_certificate(self, private_key, common_name):
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert_builder = x509.CertificateBuilder(
            issuer_name=issuer,
            subject_name=issuer,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.utcnow(),
            not_valid_after=datetime.utcnow() + timedelta(days=10)
        ).add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=1
            ),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )
        cert = cert_builder.sign(private_key,
                                 hashes.SHA256(),
                                 default_backend())
        return cert

    def _store_cert(self, cert):
        pem_encoding = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_b64 = base64.b64encode(pem_encoding)
        expire_time = (datetime.utcnow() + timedelta(days=5))
        LOG.debug("Uploading certificate to barbican")
        result = self.secret_client.create_secret(
            expiration=expire_time.isoformat(), algorithm="rsa",
            secret_type="certificate",
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64",
            payload=cert_b64
        )
        LOG.debug("Certificate uploaded to barbican (%s)", result)
        return self._get_uuid(result['secret_ref'])

    def _sign_image(self, image_file):
        LOG.debug("Creating signature for image data")
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        chunk_bytes = 8192
        with open(image_file, 'rb') as f:
            chunk = f.read(chunk_bytes)
            while len(chunk) > 0:
                hasher.update(chunk)
                chunk = f.read(chunk_bytes)
        digest = hasher.finalize()
        signature = self.private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        signature_b64 = base64.b64encode(signature)
        return signature_b64

    def sign_and_upload_image(self):
        img_signature = self._sign_image(self.img_file)

        img_properties = {
            'img_signature': img_signature,
            'img_signature_certificate_uuid': self.signing_cert_uuid,
            'img_signature_key_type': 'RSA-PSS',
            'img_signature_hash_method': 'SHA-256',
        }

        LOG.debug("Uploading image with signature metadata properties")
        img_uuid = self._image_create(
            'signed_img',
            CONF.scenario.img_container_format,
            self.img_file,
            disk_format=CONF.scenario.img_disk_format,
            properties=img_properties
        )
        LOG.debug("Uploaded image %s", img_uuid)

        return img_uuid

    def create_encryption_type(self, client=None, type_id=None, provider=None,
                               key_size=None, cipher=None,
                               control_location=None):
        if not client:
            client = self.admin_encryption_types_client
        if not type_id:
            volume_type = self.create_volume_type()
            type_id = volume_type['id']
        LOG.debug("Creating an encryption type for volume type: %s", type_id)
        client.create_encryption_type(
            type_id, provider=provider, key_size=key_size, cipher=cipher,
            control_location=control_location)
