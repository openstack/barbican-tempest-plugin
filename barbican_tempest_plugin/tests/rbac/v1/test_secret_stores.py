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

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base


CONF = config.CONF


class BarbicanV1RbacSecretStores:

    @abc.abstractmethod
    def test_list_secret_stores(self):
        """Test getting a list of all backends

        Testing: GET /v1/secret-stores
        This test must check:
          * whether the persona can list all secret stores
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_secret_store(self):
        """Test get secret store information

        Testing: GET /v1/secret-stores/{secret-store-id}
        This test must check:
          * whether the persona can get information about a specific
            secret store
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_global_secret_store(self):
        """Test getting the global secret store

        Testing: GET /v1/secret-stores/global-default
        This test must check:
          * whether the persona can get information about the global
            default secret store
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_preferred_secret_store(self):
        """Test getting the preferred secret store

        Testing: GET /v1/secret-stores/preferred
        This test must check:
          * whether the persona can get information about their project's
            preferred secret store
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_set_preferred_secret_store(self):
        """Test setting the preferred secret store

        Testing: POST /v1/secret-stores/{secret-store-id}/preferred
        This test must check:
          * whether the persona can set their project's preferred
            secret store
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_unset_preferred_secret_store(self):
        """Test removing the preferred secret store

        Testing: DELETE /v1/secret-stores/{secret-store-id}/preferred
        This test must check:
          * whether the persona can set their project's preferred
            secret store
        """
        raise NotImplementedError


class ProjectMemberTests(base.BarbicanV1RbacBase, BarbicanV1RbacSecretStores):

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.barbican_tempest.enable_multiple_secret_stores:
            raise cls.skipException("enable_multiple_secret_stores is not "
                                    "configured.  Skipping RBAC tests.")

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.SecretStoresClient()

    @decorators.idempotent_id('bf31560c-42e5-4afc-b1d6-a3a8aa7773d3')
    def test_list_secret_stores(self):
        resp = self.do_request('list_secret_stores')
        self.assertIn('secret_stores', resp)

    @decorators.idempotent_id('28d8e43b-af38-4985-8f70-3c1098116561')
    def test_get_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        resp = self.do_request('get_secret_store',
                               secret_store_id=secret_store_id)
        self.assertEqual(secret_store_id,
                         self.ref_to_uuid(resp['secret_store_ref']))

    @decorators.idempotent_id('e97d0cbe-112c-490e-b3d7-02981161d471')
    def test_get_global_secret_store(self):
        resp = self.do_request('get_global_secret_store')
        self.assertTrue(resp['global_default'])

    @decorators.idempotent_id('c3554210-8960-4d09-a1ba-369b8df6ca1f')
    def test_get_preferred_secret_store(self):
        # First use project admin to set preferred secret store
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        admin_client = self.os_project_admin.secret_v1.SecretStoresClient()
        self.do_request('set_preferred_secret_store',
                        client=admin_client,
                        secret_store_id=secret_store_id)

        # Check that other users in project can view the newly set
        # preferred secret store
        resp = self.do_request('get_preferred_secret_store')
        self.assertEqual('ACTIVE', resp['status'])

    @decorators.idempotent_id('ada28e3a-ec67-4994-9dde-410463d6d06e')
    def test_set_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('set_preferred_secret_store',
                        expected_status=exceptions.Forbidden,
                        secret_store_id=secret_store_id)

    @decorators.idempotent_id('c3f52fd1-5d18-498f-81b2-45df5cb09a87')
    def test_unset_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('unset_preferred_secret_store',
                        expected_status=exceptions.Forbidden,
                        secret_store_id=secret_store_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.SecretStoresClient()

    @decorators.idempotent_id('c459deb6-6447-43c4-820b-384903e700cb')
    def test_set_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('set_preferred_secret_store',
                        secret_store_id=secret_store_id)
        resp = self.do_request('get_preferred_secret_store')
        self.assertEqual(secret_store_id,
                         self.ref_to_uuid(resp['secret_store_ref']))

    @decorators.idempotent_id('d21ca9b6-b62e-43d1-9c9f-a6e16c939c01')
    def test_unset_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('set_preferred_secret_store',
                        secret_store_id=secret_store_id)
        self.do_request('unset_preferred_secret_store',
                        secret_store_id=secret_store_id)
        self.do_request('get_preferred_secret_store',
                        expected_status=exceptions.NotFound)


class ProjectReaderTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.SecretStoresClient()
