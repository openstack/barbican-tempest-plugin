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

from tempest.lib import decorators
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base


class BarbicanV1RbacTransportKeys:

    @abc.abstractmethod
    def test_list_transport_keys(self):
        """Test listing the transport keys

        Testing: GET /v1/transport_keys
        This test case must check:
          * whether the persona can list the available transport keys
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_transport_key(self):
        """Test creating a transport key

        Testing: POST /v1/transport_keys
        This test case must check:
          * whether the persona can create a new transport key entry
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_transport_key(self):
        """Test getting a specific transport key

        Testing: GET /v1/transport_keys/{transport-key-id}
        This test case must check:
          * whether the persona can retrieve a specific transport key
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_transport_key(self):
        """Test deleting a specific transport key

        Testing: DELETE /v1/transport_keys/{transport-key-id}
        This test case must check:
          * whether the persona can delete a specific transport key
        """
        raise NotImplementedError


class ProjectMemberTests(base.BarbicanV1RbacBase, BarbicanV1RbacTransportKeys):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.TransportKeyClient()

    @decorators.idempotent_id('dc647930-d89d-449c-8bf6-b0aff0cd95da')
    def test_list_transport_keys(self):
        resp = self.do_request('list_transport_keys')
        self.assertIn('transport_keys', resp)

    @decorators.idempotent_id('981d9ec3-7974-40ab-abf0-d19cd17311e0')
    def test_create_transport_key(self):
        self.do_request('create_transport_key',
                        expected_status=exceptions.Forbidden,
                        plugin_name='simple-crypto',
                        transport_key='???')

    @decorators.idempotent_id('4d4d46df-ec90-4755-a6e3-aa0ff9204113')
    def test_get_transport_key(self):
        # TODO(redorobot):
        # We need to sort out how system admins create keys before we
        # can test this.
        #
        # resp = self.do_request('list_transport_keys')
        # transport_key_id = self.ref_to_uuid(
        #     resp['transport_keys'][0]['transport_key_ref']
        # )
        # resp = self.do_request('get_transport_key',
        #                        transport_key_id=transport_key_id)
        # self.assertEqual(transport_key_id, resp['transport_key_id'])
        pass

    @decorators.idempotent_id('aeae2541-af87-40d6-a4b6-767fcb7416d4')
    def test_delete_transport_key(self):
        # TODO(redorobot):
        # We need to sort out how system admins create keys before we
        # can test this.
        #
        # resp = self.do_request('list_transport_keys')
        # transport_key_id = self.ref_to_uuid(
        #     resp['transport_keys'][0]['transport_key_ref']
        # )
        # resp = self.do_request('delete_transport_key',
        #                        expected_status=exceptions.Forbidden,
        #                        transport_key_id=transport_key_id)
        pass


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.TransportKeyClient()

    @decorators.idempotent_id('bed9bace-9b44-448b-b68e-bff46c4c181e')
    def test_create_transport_key(self):
        transport_key = self.client.create_transport_key(
            plugin_name="simple-crypto",
            transport_key="UUUU-UUUU-IIII-DDDD"
        )
        self.assertIn("transport_key_ref", transport_key)


class ProjectReaderTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.TransportKeyClient()
