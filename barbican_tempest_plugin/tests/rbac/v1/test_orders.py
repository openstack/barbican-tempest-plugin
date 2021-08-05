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

    def test_list_orders(self):
        self.assertRaises(exceptions.Forbidden, self.client.list_orders)

    def test_create_order(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.create_test_order,
            self.client,
            'create_orders_s'
        )

    def test_get_order(self):
        order_id = self.create_test_order(self.order_client, 'test_get_order')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_order,
            order_id=order_id)

    def test_delete_order(self):
        order_id = self.create_test_order(self.order_client,
                                          'test_delete_order')
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_order,
            order_id=order_id)

    def test_get_other_project_order(self):
        order_id = self.create_test_order(
            self.other_order_client,
            'test_get_other_project_order')
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_order,
            order_id)

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

    def test_list_orders(self):
        _ = self.create_test_order(self.order_client, 'test_list_orders')
        resp = self.client.list_orders()
        self.assertGreaterEqual(len(resp['orders']), 1)

    def test_create_order(self):
        self.create_test_order(self.client, 'create_orders_s')

    def test_get_order(self):
        order_id = self.create_test_order(self.order_client, 'test_get_order')
        resp = self.client.get_order(order_id)
        self.assertEqual(order_id, self.client.ref_to_uuid(resp['order_ref']))

    def test_delete_order(self):
        order_id = self.create_test_order(self.order_client,
                                          'test_delete_order')
        self.client.delete_order(order_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.OrderClient()
