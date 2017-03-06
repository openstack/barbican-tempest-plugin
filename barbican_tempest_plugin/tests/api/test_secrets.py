# Copyright 2016 SAP SE
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tempest.lib import decorators

from barbican_tempest_plugin.tests.api import base


class SecretsTest(base.BaseKeyManagerTest):
    """Secrets API tests."""
    @decorators.idempotent_id('d5fb4ae4-c418-4405-9701-95fc6877aeb9')
    def test_create_delete_empty_secret(self):
        sec = self.create_secret()
        uuid = base._get_uuid(sec['secret_ref'])
        self.delete_secret(uuid)

    @decorators.idempotent_id('9aee2ad3-5b61-4451-8ccc-a727bbe4618a')
    def test_create_delete_symmetric_key(self):
        password = b"password"
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=1000, backend=default_backend()
        )
        key = base64.b64encode(kdf.derive(password))
        expire_time = (datetime.utcnow() + timedelta(days=5))
        sec = self.create_secret(
            expiration=expire_time.isoformat(), algorithm="aes",
            bit_length=256, mode="cbc", payload=key,
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64"
        )
        uuid = base._get_uuid(sec['secret_ref'])
        self.delete_secret(uuid)

    @decorators.idempotent_id('79ec555d-215d-4006-bcf0-ab4c6cb0b9ff')
    def test_list_secrets(self):
        # Create two secrets
        self.create_secret(name='secret_1')
        self.create_secret(name='secret_2')

        # Ask Barbican to list these secrets
        resp = self.secret_client.list_secrets(name='secret_1')
        secrets = resp['secrets']
        self.assertEqual('secret_1', secrets[0]['name'])

        resp = self.secret_client.list_secrets(name='secret_2')
        secrets = resp['secrets']
        self.assertEqual('secret_2', secrets[0]['name'])

    @decorators.idempotent_id('f5608620-f1f7-45a5-ac0a-e1c17d1f2f42')
    def test_get_secret_metadata(self):
        secret = self.create_secret()
        uuid = base._get_uuid(secret['secret_ref'])
        resp = self.secret_client.get_secret_metadata(uuid)
        self.assertEqual(uuid, base._get_uuid(resp['secret_ref']))
        self.delete_secret(uuid)

    @decorators.idempotent_id('c5caa619-1e43-4724-8d94-a61ff7025a07')
    def test_get_and_put_payload(self):
        # Create secret without payload
        secret = self.create_secret()
        uuid = base._get_uuid(secret['secret_ref'])

        # Create AES key payload
        password = b"password"
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=1000, backend=default_backend()
        )
        key = base64.b64encode(kdf.derive(password))

        # Associate the payload with the created secret
        self.secret_client.put_secret_payload(uuid, key)

        # Retrieve the payload
        payload = self.secret_client.get_secret_payload(uuid)
        self.assertEqual(key, base64.b64encode(payload))

        # Clean up
        self.delete_secret(uuid)
