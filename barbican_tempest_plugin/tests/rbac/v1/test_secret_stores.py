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
        """TODO(redrobot): Run this with multiple backends

        We need to set up the devstack plugin to use multiple backends
        so we can run these tests.
        """
        if not CONF.barbican_tempest.enable_multiple_secret_stores:
            raise cls.skipException("enable_multiple_secret_stores is not "
                                    "configured.  Skipping RBAC tests.")

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.SecretStoresClient()

    def test_list_secret_stores(self):
        resp = self.do_request('list_secret_stores')
        self.assertIn('secret_stores', resp)

    def test_get_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        resp = self.do_request('get_secret_store',
                               secret_store_id=secret_store_id)
        self.assertEqual(secret_store_id,
                         self.ref_to_uuid(resp['secret_store_ref']))

    def test_get_global_secret_store(self):
        resp = self.do_request('get_global_secret_store')
        self.assertTrue(resp['global_default'])

    def test_get_preferred_secret_store(self):
        resp = self.do_request('get_preferred_secret_store')
        self.assertEqual('ACTIVE', resp['status'])

    def test_set_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('set_preferred_secret_store',
                        expected_status=exceptions.Forbidden,
                        secret_store_id=secret_store_id)

    def test_unset_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('unset_peferred_secret_store',
                        expected_status=exceptions.Forbidden,
                        secret_store_id=secret_store_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.SecretStoresClient()

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

    def test_unset_preferred_secret_store(self):
        resp = self.do_request('list_secret_stores')
        secret_store_id = self.ref_to_uuid(
            resp['secret_stores'][0]['secret_store_ref']
        )
        self.do_request('set_preferred_secret_store',
                        secret_store_id=secret_store_id)
        self.do_request('unset_peferred_secret_store',
                        secret_store_id=secret_store_id)
        resp = self.do_request('get_preferred_secret_store')
        self.assertEqual(secret_store_id,
                         self.ref_to_uuid(resp['secret_store_ref']))


class ProjectReaderTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.SecretStoresClient()
