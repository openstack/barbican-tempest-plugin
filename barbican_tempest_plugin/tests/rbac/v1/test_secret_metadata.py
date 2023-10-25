# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base


class BarbicanV1RbacSecretMetadata:

    @abc.abstractmethod
    def test_create_key_value_pair(self):
        """Test create_key_value_pair policy

        Testing: POST /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can add metadata to a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_secret_metadata(self):
        """Test put_secret_metadata policy

        Testing: PUT /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can update metadata on a secret
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_metadata(self):
        """Test get_secret_metadata policy

        Testing: GET /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can retrieve secret metadata
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_update_secret_metadata_by_key(self):
        """Test update_secret_metadata policy

        Testing: PUT /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can update individual secret metadata
            values
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_metadata_by_key(self):
        """Test get_secret_metadata_by_key policy

        Testing: GET /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can retrieve individual secret metadata
            values
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret_metadata_by_key(self):
        """Test delete_secret_metadata_by_key policy

        Testing: DELETE /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can delete individual secret metadata
            values
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_key_value_pair_on_other_secret(self):
        """Test create_key_value_pair policy

        Testing: POST /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can add metadata to a secret
            that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_put_secret_metadata_on_other_secret(self):
        """Test put_secret_metadata policy

        Testing: PUT /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can update metadata on a secret
            that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_metadata_from_other_secret(self):
        """Test get_secret_metadata policy

        Testing: GET /v1/secrets/{secret-id}/metadata
        This test must check:
          * whether the persona can retrieve secret metadata
            from a secret that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_update_other_secret_metadata_by_key(self):
        """Test update_secret_metadata policy

        Testing: PUT /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can update individual secret metadata
            values on a secret that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_other_secret_metadata_by_key(self):
        """Test get_secret_metadata_by_key policy

        Testing: GET /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can retrieve individual secret metadata
            values for a secret that belongs to a different project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_other_secret_metadata_by_key(self):
        """Test delete_secret_metadata policy

        Testing: DELETE /v1/secrets/{secret-id}/metadata/{meta-key}
        This test must check:
          * whether the persona can delete individual secret metadata
            values
        """
        raise NotImplementedError


class ProjectReaderTests(base.BarbicanV1RbacBase,
                         BarbicanV1RbacSecretMetadata):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.SecretMetadataClient()

    def setUp(self):
        super().setUp()
        self.secret_id = self.create_test_secret(
            self.secret_client,
            data_utils.rand_name('test-secret-metadata'),
            'SECRET_PASSPHRASE')
        self.secret_metadata_client.create_key_value_pair(
            self.secret_id,
            'foo',
            'bar')

        self.other_secret_id = self.create_test_secret(
            self.other_secret_client,
            data_utils.rand_name('test-secret-metadata'),
            'SECRET_PASSPHRASE')
        self.other_secret_metadata_client.create_key_value_pair(
            self.other_secret_id,
            'foo',
            'bar')

    @decorators.idempotent_id('2dd1cb04-67e9-4c3c-a40e-12184eff5bc6')
    def test_create_key_value_pair(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_key_value_pair,
            self.secret_id,
            'mykey',
            'foo'
        )

    @decorators.idempotent_id('33c1d271-5367-4f0e-a2e7-c28ea1130fa6')
    def test_put_secret_metadata(self):
        meta = {
            'foo': 'bar',
            'baz': 'bork'
        }
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_metadata,
            self.secret_id,
            **meta)

    @decorators.idempotent_id('8f22488b-52d5-4a28-ae32-faf1514ef390')
    def test_get_secret_metadata(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            self.secret_id)

    @decorators.idempotent_id('df6bbafc-f836-44b4-a0a7-3d0f94f5b9ac')
    def test_update_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.update_secret_metadata,
            self.secret_id,
            'foo',
            'baz')

    @decorators.idempotent_id('b2f3bafb-4a21-47da-966f-3e3010571596')
    def test_get_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata_by_key,
            self.secret_id,
            'foo')

    @decorators.idempotent_id('0d80db72-fc6f-445f-b402-f86c91233b4f')
    def test_delete_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_metadata_by_key,
            self.secret_id,
            'foo')

    @decorators.idempotent_id('7c6223b6-5a2f-4989-ae54-db253702af98')
    def test_create_key_value_pair_on_other_secret(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_key_value_pair,
            self.other_secret_id,
            'mykey',
            'foo'
        )

    @decorators.idempotent_id('c1738dd5-e67a-4b48-8064-c198ca0a7970')
    def test_put_secret_metadata_on_other_secret(self):
        meta = {
            'foo': 'bar',
            'baz': 'bork'
        }
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_secret_metadata,
            self.other_secret_id,
            **meta)

    @decorators.idempotent_id('efb8d207-5418-4c3a-bb30-d1d5e1695c41')
    def test_get_secret_metadata_from_other_secret(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata,
            self.other_secret_id)

    @decorators.idempotent_id('489d52ae-3324-420b-b69c-938f2eb41f6f')
    def test_update_other_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.update_secret_metadata,
            self.other_secret_id,
            'foo',
            'baz')

    @decorators.idempotent_id('f2cbaec3-94ff-4a9c-bc2d-4c728f46313b')
    def test_get_other_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_secret_metadata_by_key,
            self.other_secret_id,
            'foo')

    @decorators.idempotent_id('fb581f6c-1d59-420c-b05b-227514c75789')
    def test_delete_other_secret_metadata_by_key(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_metadata_by_key,
            self.other_secret_id,
            'foo')


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.secret_metadata_client

    @decorators.idempotent_id('73d4c9cc-b7ad-4706-bec4-e7dc70698711')
    def test_create_key_value_pair(self):
        resp = self.client.create_key_value_pair(
            self.secret_id,
            'mykey',
            'foo'
        )
        self.assertEqual('mykey', resp['key'])
        self.assertEqual('foo', resp['value'])

    @decorators.idempotent_id('f7178757-5ae4-4041-a57c-322f7665f055')
    def test_put_secret_metadata(self):
        test_meta = {
            'foo': 'baz',
            'bar': 'bork'
        }
        self.client.put_secret_metadata(self.secret_id, **test_meta)
        resp = self.client.get_secret_metadata(self.secret_id)

        self.assertIn('bar', resp.keys())
        self.assertEqual('baz', resp['foo'])

    @decorators.idempotent_id('054348d4-c4b4-446a-ad98-c79f6de42eec')
    def test_get_secret_metadata(self):
        resp = self.client.get_secret_metadata(self.secret_id)

        self.assertIn('foo', resp.keys())
        self.assertEqual('bar', resp['foo'])

    @decorators.idempotent_id('7ed07736-39e7-4c4f-b5c9-f59017f3e80b')
    def test_update_secret_metadata_by_key(self):
        self.client.update_secret_metadata(self.secret_id, 'foo', 'baz')

        resp = self.secret_metadata_client.get_secret_metadata(self.secret_id)
        self.assertEqual('baz', resp['foo'])

    @decorators.idempotent_id('26160af4-ff17-4023-9238-a2a9dca9946c')
    def test_get_secret_metadata_by_key(self):
        resp = self.client.get_secret_metadata_by_key(self.secret_id, 'foo')
        self.assertEqual('foo', resp['key'])
        self.assertEqual('bar', resp['value'])

    @decorators.idempotent_id('3740d6ec-304f-43ce-aa54-af62006715d8')
    def test_delete_secret_metadata_by_key(self):
        self.client.delete_secret_metadata_by_key(self.secret_id, 'foo')
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_secret_metadata_by_key,
            self.secret_id,
            'foo')


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.admin_secret_metadata_client
