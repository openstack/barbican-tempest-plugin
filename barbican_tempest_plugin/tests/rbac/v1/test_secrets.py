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
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base as rbac_base


CONF = config.CONF


class BarbicanV1RbacSecrets:

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

    @abc.abstractmethod
    def test_get_other_project_secret(self):
        """Test get_secrets policy

        Testing: GET /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can get secret metadata for a secret that
            belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_other_project_secret_payload(self):
        """Test get_secrets policy

        Testing: GET /v1/secrets/{secret_id}/payload
        This test must check:
          * whether the persona can get secret payload for a secret that
            belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_other_project_secret_payload(self):
        """Test put_secret policy.

        Testing: PUT /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can PUT the secret payload in a 2-step
            create when the first step is done by a member of a different
            project.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_other_project_secret(self):
        """Test delete_secret policy.

        Testing: DELETE /v1/secrets/{secret_id}
        This test must check:
          * whether the persona can delete a secret that belongs to a
            different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_acl(self):
        """Test GET /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can get the ACL for a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_secret_acl(self):
        """Test PUT /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can overwrite the ACL for a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_patch_secret_acl(self):
        """Test PATCH /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can modify the ACL for a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret_acl(self):
        """Test DELETE /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can delete the ACL for a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_other_secret_acl(self):
        """Test GET /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can get the ACL for a secret
            that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_other_secret_acl(self):
        """Test PUT /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can overwrite the ACL for a secret
            that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_patch_other_secret_acl(self):
        """Test PATCH /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can modify the ACL for a secret
            that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_other_secret_acl(self):
        """Test DELETE /v1/secrets/{secret_id}/acl policy

        This test must check:
          * whether the persona can delete the ACL for a secret
            that belongs to a different project
        """
        raise NotImplementedError


class BarbicanV1_1SecretConsumers:

    @abc.abstractmethod
    def test_list_secret_consumers(self):
        """Test list_secret_consumers policy

        Testing: GET /v1/secrets/{secret-id}/consumers
        This test must check:
          * whether the persona can list a secrets consumers
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_secret_consumer(self):
        """Test create_secret_consumer policy

        Testing: POST /v1/secrets/{secret-id}/consumers
        This test must check:
          * whether the persona can create a consumer of the secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret_consumer(self):
        """Test delete_secret_consumer policy

        Testing: DELETE /v1/secrets/{secret-id}/consumers
        This test must check:
          * whether the persona can delete a consumer of the secret
        """
        raise NotImplementedError


class ProjectReaderBase(rbac_base.BarbicanV1RbacBase):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.SecretClient()

    def setUp(self):
        super().setUp()
        self.secret_id = self.create_test_secret(
            self.secret_client,
            data_utils.rand_name('test-secrets'),
            'THIS_IS_A_SECRET_PASSPHRASE')
        self.other_secret_id = self.create_test_secret(
            self.other_secret_client,
            data_utils.rand_name('test-secrets'),
            'THIS_IS_SOMEONE_ELSES_SECRET_PASSPHRASE')
        self.valid_acl = {
            "read": {
                "users": [self.other_secret_client.user_id],
                "project-access": True
            }
        }


class ProjectReaderTests(ProjectReaderBase, BarbicanV1RbacSecrets):

    def test_create_secret(self):
        """Test add_secret policy."""
        self.assertRaises(exceptions.Forbidden, self.client.create_secret)

        key = rbac_base.create_aes_key()
        expire_time = (datetime.utcnow() + timedelta(days=5))

        self.assertRaises(
            exceptions.Forbidden, self.client.create_secret,
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
        self.assertRaises(
            exceptions.Forbidden,
            self.client.list_secrets,
            name='secret_1'
        )

        # list secrets with name secret_2
        self.assertRaises(
            exceptions.Forbidden,
            self.client.list_secrets,
            name='secret_2'
        )

        # list all secrets
        self.assertRaises(exceptions.Forbidden, self.client.list_secrets)

    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret,
            secret_id=uuid
        )

    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            secret_id=uuid
        )

    def test_get_secret_payload(self):
        """Test get_secret payload policy."""
        key, sec = self.create_aes_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        # Retrieve the payload
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_payload,
            secret_id=uuid
        )

    def test_put_secret_payload(self):
        """Test put_secret policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        key = rbac_base.create_aes_key()

        # Associate the payload with the created secret
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_payload,
            secret_id=uuid, payload=key
        )

    def test_get_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_secret',
            payload='¡Muy secreto!')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            other_secret_id)

    def test_get_other_project_secret_payload(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_payload',
            payload='¡Más secreto!')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_payload,
            other_secret_id)

    def test_put_other_project_secret_payload(self):
        other_secret_id = self.create_other_project_secret('put_other_payload')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_payload,
            other_secret_id,
            'Shhhh... secret!')

    def test_delete_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_payload',
            payload='loremipsumloremipsum')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret,
            other_secret_id)

    def test_get_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_acl,
            self.secret_id)

    def test_put_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_acl,
            self.secret_id,
            self.valid_acl)

    def test_patch_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.patch_secret_acl,
            self.secret_id,
            self.valid_acl)

    def test_delete_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_acl,
            self.secret_id)

    def test_get_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_acl,
            self.other_secret_id)

    def test_put_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_acl,
            self.other_secret_id,
            self.valid_acl)

    def test_patch_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.patch_secret_acl,
            self.other_secret_id,
            self.valid_acl)

    def test_delete_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_acl,
            self.other_secret_id)


class ProjectReaderV1_1Tests(ProjectReaderBase, BarbicanV1_1SecretConsumers):

    min_microversion = '1.1'

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.secret_consumer_client = \
            cls.os_project_reader.secret_v1_1.SecretConsumerClient()

    def setUp(self):
        super().setUp()
        self.test_consumer = {
            "service": "service1",
            "resource_id": "resource_id1",
            "resource_type": "resource_type1"
        }
        self.member_secret_consumer_client.add_consumer_to_secret(
            self.secret_id,
            **self.test_consumer
        )

    def test_list_secret_consumers(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_consumer_client.list_consumers_in_secret,
            self.secret_id)

    def test_create_secret_consumer(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_consumer_client.add_consumer_to_secret,
            self.secret_id,
            **self.test_consumer)

    def test_delete_secret_consumer(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_consumer_client.delete_consumer_from_secret,
            self.secret_id,
            **self.test_consumer)


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client

    def test_create_secret(self):
        """Test add_secret policy."""
        self.client.create_secret(name='test_create_secret')

        key = rbac_base.create_aes_key()
        expire_time = (datetime.utcnow() + timedelta(days=5))
        self.client.create_secret(
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
        resp = self.client.list_secrets(name='test_list_secrets')
        secrets = resp['secrets']
        self.assertEqual('test_list_secrets', secrets[0]['name'])

        # list secrets with name secret_2
        resp = self.client.list_secrets(name='test_list_secrets_2')
        secrets = resp['secrets']
        self.assertEqual('test_list_secrets_2', secrets[0]['name'])

        # list all secrets
        resp = self.client.list_secrets()
        secrets = resp['secrets']
        self.assertGreaterEqual(len(secrets), 2)

    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('test_delete_secret_1')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])
        self.client.delete_secret(uuid)

    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('test_get_secret')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])
        resp = self.client.get_secret_metadata(uuid)
        self.assertEqual(uuid, self.client.ref_to_uuid(resp['secret_ref']))

    def test_get_secret_payload(self):
        """Test get_secret payload policy."""
        key, sec = self.create_aes_secret_admin('test_get_secret_payload')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])

        # Retrieve the payload
        payload = self.client.get_secret_payload(uuid)
        self.assertEqual(key, base64.b64encode(payload))

    def test_put_secret_payload(self):
        """Test put_secret policy."""
        sec = self.create_empty_secret_admin('test_put_secret_payload')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])

        key = rbac_base.create_aes_key()

        # Associate the payload with the created secret
        self.client.put_secret_payload(uuid, key)

        # Retrieve the payload
        payload = self.client.get_secret_payload(uuid)
        self.assertEqual(key, base64.b64encode(payload))

    def test_get_secret_acl(self):
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertIn("read", acl.keys())

    def test_put_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.other_secret_client.get_secret_metadata,
            self.secret_id
        )
        _ = self.client.put_secret_acl(self.secret_id, self.valid_acl)
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])
        resp = self.other_secret_client.get_secret_metadata(self.secret_id)
        self.assertIn(self.secret_id, resp['secret_ref'])

    def test_patch_secret_acl(self):
        _ = self.client.put_secret_acl(self.secret_id, self.valid_acl)
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])
        clear_users_acl = {
            'read': {
                'users': []
            }
        }
        _ = self.client.patch_secret_acl(self.secret_id, clear_users_acl)
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertNotIn(self.other_secret_client.user_id,
                         acl['read']['users'])

    def test_delete_secret_acl(self):
        _ = self.client.put_secret_acl(self.secret_id, self.valid_acl)
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])

        _ = self.client.delete_secret_acl(self.secret_id)

        acl = self.client.get_secret_acl(self.secret_id)
        self.assertNotIn('users', acl['read'].keys())


class ProjectMemberV1_1Tests(ProjectReaderV1_1Tests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.secret_consumer_client = cls.member_secret_consumer_client

    def test_list_secret_consumers(self):
        resp = self.secret_consumer_client.list_consumers_in_secret(
            self.secret_id
        )
        self.assertEqual(1, resp['total'])

    def test_create_secret_consumer(self):
        second_consumer = {
            'service': 'service2',
            'resource_id': 'resource_id2',
            'resource_type': 'resource_type2'
        }

        resp = self.secret_consumer_client.add_consumer_to_secret(
            self.secret_id,
            **second_consumer)

        self.assertEqual(2, len(resp['consumers']))

    def test_delete_secret_consumer(self):
        resp = self.secret_consumer_client.delete_consumer_from_secret(
            self.secret_id,
            **self.test_consumer)

        self.assertEqual(0, len(resp['consumers']))


class ProjectAdminTests(ProjectMemberTests):
    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.admin_secret_client


class ProjectAdminV1_1Tests(ProjectMemberV1_1Tests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.secret_consumer_client = cls.admin_secret_consumer_client

    def test_create_secret_consumer(self):
        pass

    def test_delete_secret_consumer(self):
        pass

    def test_list_secret_consumers(self):
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

    def test_get_other_project_secret(self):
        pass

    def test_get_other_project_secret_payload(self):
        pass

    def test_put_other_project_secret_payload(self):
        pass

    def test_delete_other_project_secret(self):
        pass

    def test_get_secret_acl(self):
        pass

    def test_put_secret_acl(self):
        pass

    def test_patch_secret_acl(self):
        pass

    def test_delete_secret_acl(self):
        pass

    def test_get_other_secret_acl(self):
        pass

    def test_put_other_secret_acl(self):
        pass

    def test_patch_other_secret_acl(self):
        pass

    def test_delete_other_secret_acl(self):
        pass


class SystemMemberTests(SystemReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client


class SystemAdminTests(SystemMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client
