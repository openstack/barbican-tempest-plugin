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


class BarbicanV1RbacOrders:

    @abc.abstractmethod
    def test_list_orders(self):
        """Test list_orders policy

        Testing GET /v1/orders
        This test must check:
          * whether persona can list orders
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_order(self):
        """Test create_order policy

        Testing POST /v1/orders
        This test must check:
          * whether persona can create orders
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_order(self):
        """Test get_order policy

        Testing GET /v1/orders/{order-id}
        This test must check:
          * whether persona can get order information
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_order(self):
        """Test delete_order policy

        Testing DELETE /v1/orders/{order-id}
        This test must check:
          * whether persona can delete orders
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_other_project_order(self):
        """Test get_order policy

        Testing GET /v1/orders/{order-id}
        This test must check:
          * whether persona can get order information
            for an order that belongs to a different
            project
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_other_project_order(self):
        """Test delete_order policy

        Testing DELETE /v1/orders/{order-id}
        This test must check:
          * whether persona can delete orders
            that belong to a different project
        """
        raise NotImplementedError


class ProjectReaderTests(base.BarbicanV1RbacBase, BarbicanV1RbacOrders):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.OrderClient()

    @decorators.idempotent_id('78c66385-c8ae-44a7-942e-5e1f87072198')
    def test_list_orders(self):
        self.assertRaises(exceptions.Forbidden, self.client.list_orders)

    @decorators.idempotent_id('fa5f861d-a376-437d-ab88-b3eea9a20403')
    def test_create_order(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.create_test_order,
            self.client,
            'create_orders_s'
        )

    @decorators.idempotent_id('39227b64-4d99-42ce-9acb-0fc4df2949ab')
    def test_get_order(self):
        order_id = self.create_test_order(self.order_client, 'test_get_order')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_order,
            order_id=order_id)

    @decorators.idempotent_id('ca5ef19c-19f3-45fd-a20d-920c1bb6414c')
    def test_delete_order(self):
        order_id = self.create_test_order(self.order_client,
                                          'test_delete_order')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_order,
            order_id=order_id)

    @decorators.idempotent_id('9689c961-2b91-4d4d-b3f3-4f185e7ae1cc')
    def test_get_other_project_order(self):
        order_id = self.create_test_order(
            self.other_order_client,
            'test_get_other_project_order')
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_order,
            order_id)

    @decorators.idempotent_id('ee9d022c-90d5-427b-b430-b10323270a49')
    def test_delete_other_project_order(self):
        order_id = self.create_test_order(
            self.other_order_client,
            'test_delete_other_project_order')
        self.assertRaises(
            exceptions.NotFound,
            self.client.delete_order,
            order_id)


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.OrderClient()

    @decorators.idempotent_id('789262f2-34fd-46c3-824a-f780d5b5c603')
    def test_list_orders(self):
        _ = self.create_test_order(self.order_client, 'test_list_orders')
        resp = self.client.list_orders()
        self.assertGreaterEqual(len(resp['orders']), 1)

    @decorators.idempotent_id('898154b7-b4e0-44d8-bf84-e87de5d0b48b')
    def test_create_order(self):
        self.create_test_order(self.client, 'create_orders_s')

    @decorators.idempotent_id('798c715d-37fb-4c8b-89c5-e679b016fde7')
    def test_get_order(self):
        order_id = self.create_test_order(self.order_client, 'test_get_order')
        resp = self.client.get_order(order_id)
        self.assertEqual(order_id, self.client.ref_to_uuid(resp['order_ref']))

    @decorators.idempotent_id('fe26f0a1-bcfe-449d-8fd1-ccc4c28f13c2')
    def test_delete_order(self):
        order_id = self.create_test_order(self.order_client,
                                          'test_delete_order')
        self.client.delete_order(order_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.OrderClient()
