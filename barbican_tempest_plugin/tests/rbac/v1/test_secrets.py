# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc
import base64
from datetime import datetime
from datetime import timedelta

from tempest import config
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base as rbac_base

CONF = config.CONF


class BarbicanV1RbacSecrets(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def test_create_secret(self):
        """Test add_secret policy.

        Testing: POST /v1/secrets
        This test must check:
          * whether the persona can create an empty secret
          * whether the persona can create a secret with a symmetric key
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_list_secrets(self):
        """Test get_secrets policy.

        Testing: GET /v1/secrets
        This test must check:
          * whether the persona can list secrets within their project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret(self):
        """Test deleting a secret.

        Testing: DEL /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can delete a secret in their project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret(self):
        """Test get_secret policy.

        Testing: GET /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can get a specific secret within their project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_payload(self):
        """Test get_secret payload policy.

        Testing: GET /v1/secrets/{secret_id}/payload
        This test must check:
          * whether the persona can get a secret payload
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_secret_payload(self):
        """Test put_secret policy.

        Testing: PUT /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can add a paylod to an empty secret
        """
        raise NotImplementedError


class ProjectMemberTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.SecretClient()

    def test_create_secret(self):
        """Test add_secret policy."""
        self.do_request('create_secret', expected_status=201, cleanup='secret',
                        name='test_create_secret')

        key = rbac_base.create_aes_key()
        expire_time = (datetime.utcnow() + timedelta(days=5))
        self.do_request(
            'create_secret', expected_status=201, cleanup="secret",
            name='test_create_secret2',
            expiration=expire_time.isoformat(), algorithm="aes",
            bit_length=256, mode="cbc", payload=key,
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64"
        )

    def test_list_secrets(self):
        """Test get_secrets policy."""
        # create two secrets
        self.create_empty_secret_admin('test_list_secrets')
        self.create_empty_secret_admin('test_list_secrets_2')

        # list secrets with name secret_1
        resp = self.do_request('list_secrets', name='test_list_secrets')
        secrets = resp['secrets']
        self.assertEqual('test_list_secrets', secrets[0]['name'])

        # list secrets with name secret_2
        resp = self.do_request('list_secrets', name='test_list_secrets_2')
        secrets = resp['secrets']
        self.assertEqual('test_list_secrets_2', secrets[0]['name'])

        # list all secrets
        resp = self.do_request('list_secrets')
        secrets = resp['secrets']
        self.assertGreaterEqual(len(secrets), 2)

    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('test_delete_secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        self.do_request('delete_secret', secret_id=uuid)
        self.delete_cleanup('secret', uuid)

    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('test_get_secret')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        resp = self.do_request('get_secret_metadata', secret_id=uuid)
        self.assertEqual(uuid, self.ref_to_uuid(resp['secret_ref']))

    def test_get_secret_payload(self):
        """Test get_secret payload policy."""
        key, sec = self.create_aes_secret_admin('test_get_secret_payload')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        # Retrieve the payload
        payload = self.do_request('get_secret_payload', secret_id=uuid)
        self.assertEqual(key, base64.b64encode(payload))

    def test_put_secret_payload(self):
        """Test put_secret policy."""
        sec = self.create_empty_secret_admin('test_put_secret_payload')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        key = rbac_base.create_aes_key()

        # Associate the payload with the created secret
        self.do_request('put_secret_payload', secret_id=uuid, payload=key)

        # Retrieve the payload
        payload = self.do_request('get_secret_payload', secret_id=uuid)
        self.assertEqual(key, base64.b64encode(payload))


class ProjectAdminTests(ProjectMemberTests):
    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.SecretClient()


class ProjectReaderTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.SecretClient()

    def test_create_secret(self):
        """Test add_secret policy."""
        self.do_request(
            'create_secret', expected_status=exceptions.Forbidden,
            cleanup='secret')

        key = rbac_base.create_aes_key()
        expire_time = (datetime.utcnow() + timedelta(days=5))
        self.do_request(
            'create_secret', expected_status=exceptions.Forbidden,
            cleanup="secret",
            expiration=expire_time.isoformat(), algorithm="aes",
            bit_length=256, mode="cbc", payload=key,
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64"
        )

    def test_list_secrets(self):
        """Test get_secrets policy."""
        # create two secrets
        self.create_empty_secret_admin('secret_1')
        self.create_empty_secret_admin('secret_2')

        # list secrets with name secret_1
        self.do_request(
            'list_secrets', expected_status=exceptions.Forbidden,
            name='secret_1'
        )

        # list secrets with name secret_2
        self.do_request(
            'list_secrets', expected_status=exceptions.Forbidden,
            name='secret_2'
        )

        # list all secrets
        self.do_request(
            'list_secrets', expected_status=exceptions.Forbidden
        )

    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        self.do_request(
            'delete_secret', expected_status=exceptions.Forbidden,
            secret_id=uuid
        )

    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        self.do_request(
            'get_secret_metadata', expected_status=exceptions.Forbidden,
            secret_id=uuid
        )

    def test_get_secret_payload(self):
        """Test get_secret payload policy."""
        key, sec = self.create_aes_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        # Retrieve the payload
        self.do_request(
            'get_secret_payload', expected_status=exceptions.Forbidden,
            secret_id=uuid
        )

    def test_put_secret_payload(self):
        """Test put_secret policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        key = rbac_base.create_aes_key()

        # Associate the payload with the created secret
        self.do_request(
            'put_secret_payload', expected_status=exceptions.Forbidden,
            secret_id=uuid, payload=key
        )


class SystemAdminTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client

    def test_create_secret(self):
        pass

    def test_list_secrets(self):
        pass

    def test_delete_secret(self):
        pass

    def test_get_secret(self):
        pass

    def test_get_secret_payload(self):
        pass

    def test_put_secret_payload(self):
        pass


class SystemMemberTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client

    def test_create_secret(self):
        pass

    def test_list_secrets(self):
        pass

    def test_delete_secret(self):
        pass

    def test_get_secret(self):
        pass

    def test_get_secret_payload(self):
        pass

    def test_put_secret_payload(self):
        pass


class SystemReaderTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client

    def test_create_secret(self):
        pass

    def test_list_secrets(self):
        pass

    def test_delete_secret(self):
        pass

    def test_get_secret(self):
        pass

    def test_get_secret_payload(self):
        pass

    def test_put_secret_payload(self):
        pass
