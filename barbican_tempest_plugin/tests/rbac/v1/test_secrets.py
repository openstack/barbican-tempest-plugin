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
from tempest.lib import decorators
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

    @decorators.idempotent_id('e4dfbae6-faca-42a7-a06b-2655e29df193')
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

    @decorators.idempotent_id('f2649794-10d2-4742-a81c-af78eb3d9c0e')
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

    @decorators.idempotent_id('6a4cfca5-1841-49f4-ae1d-bbde0fa94bd7')
    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])

        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret,
            secret_id=uuid
        )

    @decorators.idempotent_id('9c5b46b4-8f0b-4f75-b751-61ddf943fbf3')
    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('secret_1')
        uuid = self.ref_to_uuid(sec['secret_ref'])
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            secret_id=uuid
        )

    @decorators.idempotent_id('b2760216-e492-4081-b981-a5d40bcc6a0e')
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

    @decorators.idempotent_id('64b4e2e7-0121-46e7-949f-34332efdec6f')
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

    @decorators.idempotent_id('5219c830-fe82-4f3b-9eda-e3b5e918ba60')
    def test_get_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_secret',
            payload='¡Muy secreto!')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            other_secret_id)

    @decorators.idempotent_id('dff3d49e-9e31-46bb-b069-d4c72f591718')
    def test_get_other_project_secret_payload(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_payload',
            payload='¡Más secreto!')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_payload,
            other_secret_id)

    @decorators.idempotent_id('fb2fe2a4-2ca9-4b64-b18f-cc0877eb27bc')
    def test_put_other_project_secret_payload(self):
        other_secret_id = self.create_other_project_secret('put_other_payload')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_payload,
            other_secret_id,
            'Shhhh... secret!')

    @decorators.idempotent_id('fc2f42ec-6bf4-4121-9698-4f0a7d01d8f3')
    def test_delete_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_payload',
            payload='loremipsumloremipsum')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret,
            other_secret_id)

    @decorators.idempotent_id('effafb29-fd10-41fb-9404-585af3de3602')
    def test_get_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_acl,
            self.secret_id)

    @decorators.idempotent_id('d5058429-4e98-43ac-bda4-8160b2b95ef7')
    def test_put_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_acl,
            self.secret_id,
            self.valid_acl)

    @decorators.idempotent_id('3350274a-b3f4-4178-927f-2591ef2dbea8')
    def test_patch_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.patch_secret_acl,
            self.secret_id,
            self.valid_acl)

    @decorators.idempotent_id('07104bf1-104b-4fa5-b855-82cba69bf24c')
    def test_delete_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_acl,
            self.secret_id)

    @decorators.idempotent_id('434187eb-1dd2-4544-bb1e-6be0dca8cd25')
    def test_get_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_acl,
            self.other_secret_id)

    @decorators.idempotent_id('32312a70-8f02-4663-b7e0-4432950c2c11')
    def test_put_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_acl,
            self.other_secret_id,
            self.valid_acl)

    @decorators.idempotent_id('ad95395f-45b0-4b34-b92a-e6c25f90e798')
    def test_patch_other_secret_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.patch_secret_acl,
            self.other_secret_id,
            self.valid_acl)

    @decorators.idempotent_id('1470e2fc-46ce-4d06-a11a-201e9b5950c6')
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

    @decorators.idempotent_id('be85626b-ca83-4c90-9bf0-b918b9de21b6')
    def test_list_secret_consumers(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_consumer_client.list_consumers_in_secret,
            self.secret_id)

    @decorators.idempotent_id('d7389369-62e9-4a25-b759-2a64f72fcba2')
    def test_create_secret_consumer(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_consumer_client.add_consumer_to_secret,
            self.secret_id,
            **self.test_consumer)

    @decorators.idempotent_id('dbfba5e4-cd52-4ce9-bf50-a7e933ce5dcc')
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

    @decorators.idempotent_id('69f24625-0d8a-4412-b9c2-5a96fc689c87')
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

    @decorators.idempotent_id('ff89eaa4-0014-4935-80cf-f8b7970387e1')
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

    @decorators.idempotent_id('bffcf1e6-b9a2-43d8-b95c-b3683d6c4549')
    def test_delete_secret(self):
        """Test delete_secrets policy."""
        sec = self.create_empty_secret_admin('test_delete_secret_1')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])
        self.client.delete_secret(uuid)

    @decorators.idempotent_id('72a59d44-1967-44fc-84a1-157a7bf124fa')
    def test_get_secret(self):
        """Test get_secret policy."""
        sec = self.create_empty_secret_admin('test_get_secret')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])
        resp = self.client.get_secret_metadata(uuid)
        self.assertEqual(uuid, self.client.ref_to_uuid(resp['secret_ref']))

    @decorators.idempotent_id('cb848266-0172-4f93-add3-9d6f41a3bc46')
    def test_get_secret_payload(self):
        """Test get_secret payload policy."""
        key, sec = self.create_aes_secret_admin('test_get_secret_payload')
        uuid = self.client.ref_to_uuid(sec['secret_ref'])

        # Retrieve the payload
        payload = self.client.get_secret_payload(uuid)
        self.assertEqual(key, base64.b64encode(payload))

    @decorators.idempotent_id('f6c58ca1-50f2-4454-b3b2-b338a7dcf3cb')
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

    @decorators.idempotent_id('63482006-18b5-40d3-82da-fdc078d6e5fe')
    def test_get_secret_acl(self):
        acl = self.client.get_secret_acl(self.secret_id)
        self.assertIn("read", acl.keys())

    @decorators.idempotent_id('915bdc2a-94d2-4835-a46e-a27f16ae57a2')
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

    @decorators.idempotent_id('d6128f75-e7af-43dc-bf43-cf5fdc5f83be')
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

    @decorators.idempotent_id('d566f1ab-c318-42cc-80d9-1ff9178d2c63')
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

    @decorators.idempotent_id('ca2bbfa3-90b2-4f4e-8e57-3a3562d202a6')
    def test_list_secret_consumers(self):
        resp = self.secret_consumer_client.list_consumers_in_secret(
            self.secret_id
        )
        self.assertEqual(1, resp['total'])

    @decorators.idempotent_id('86cadb1e-f748-4d99-9477-4d171d4e9240')
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

    @decorators.idempotent_id('f56c4c14-e8c7-4335-8d84-00f34355b53c')
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

    def test_delete_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_payload',
            payload='loremipsumloremipsum')
        self.client.delete_secret(other_secret_id)

    def test_get_other_project_secret(self):
        other_secret_id = self.create_other_project_secret(
            'get_other_secret',
            payload='¡Muy secreto!')
        self.client.get_secret_metadata(other_secret_id)


class ProjectAdminV1_1Tests(ProjectMemberV1_1Tests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.secret_consumer_client = cls.admin_secret_consumer_client

    @decorators.idempotent_id('2da9bfb4-f53b-45c0-b8c9-f657ced99bd4')
    def test_create_secret_consumer(self):
        pass

    @decorators.idempotent_id('2a4eaac5-76a1-48e2-b648-b1b02344130b')
    def test_delete_secret_consumer(self):
        pass

    @decorators.idempotent_id('34e2ded6-30ea-4f8a-b4e1-3aecac8fdd49')
    def test_list_secret_consumers(self):
        pass


class SystemReaderTests(rbac_base.BarbicanV1RbacBase, BarbicanV1RbacSecrets):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_client

    @decorators.idempotent_id('104f71f0-8099-43ae-b4d9-cce5781a79b9')
    def test_create_secret(self):
        pass

    @decorators.idempotent_id('5a29b825-4f28-4733-90fa-579b63ae2b96')
    def test_list_secrets(self):
        pass

    @decorators.idempotent_id('b637c7db-64a9-46c8-b322-c4d282e05164')
    def test_delete_secret(self):
        pass

    @decorators.idempotent_id('8d0a7f54-61f3-432e-8f4b-c04945b40373')
    def test_get_secret(self):
        pass

    @decorators.idempotent_id('1bc76c3a-a69e-4285-8f8e-f7bacd01fef8')
    def test_get_secret_payload(self):
        pass

    @decorators.idempotent_id('c2f38e3d-cc52-43c0-9fb3-8065797c40da')
    def test_put_secret_payload(self):
        pass

    @decorators.idempotent_id('be392729-af43-4aab-bbc7-43fcd5df9140')
    def test_get_other_project_secret(self):
        pass

    @decorators.idempotent_id('cc021881-7fba-48a2-aa6e-68c426b382f9')
    def test_get_other_project_secret_payload(self):
        pass

    @decorators.idempotent_id('e87f5e40-7bb3-4fc8-aa5a-23cc1a8850f5')
    def test_put_other_project_secret_payload(self):
        pass

    @decorators.idempotent_id('ce878824-d424-4abb-8217-068c9a99333b')
    def test_delete_other_project_secret(self):
        pass

    @decorators.idempotent_id('be04944b-b4e2-4f66-b58a-3d047c99d939')
    def test_get_secret_acl(self):
        pass

    @decorators.idempotent_id('65ce0063-d6f1-463c-b752-d4871a9df684')
    def test_put_secret_acl(self):
        pass

    @decorators.idempotent_id('81423acc-240c-46f0-8de9-4cf6ab5d4bc4')
    def test_patch_secret_acl(self):
        pass

    @decorators.idempotent_id('d55d5798-c23f-4108-8005-963d350d9d41')
    def test_delete_secret_acl(self):
        pass

    @decorators.idempotent_id('5490d517-ba6c-4e28-8712-07dbc9bb9ada')
    def test_get_other_secret_acl(self):
        pass

    @decorators.idempotent_id('1ae61619-104a-4497-999c-00671335bc4f')
    def test_put_other_secret_acl(self):
        pass

    @decorators.idempotent_id('5ec28567-111b-405f-93c9-ed5d4259e918')
    def test_patch_other_secret_acl(self):
        pass

    @decorators.idempotent_id('65cfefb4-69a6-4f31-b8e1-defad1b57645')
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
