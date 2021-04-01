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
import time

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


class ProjectMemberTests(base.BarbicanV1RbacBase, BarbicanV1RbacOrders):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.OrderClient()

    def test_list_orders(self):
        self.do_request('create_order', cleanup='order',
                        name='list_orders', type='key',
                        meta={
                            'name': 'list_orders_s',
                            'algorithm': 'aes',
                            'bit_length': 256,
                            'mode': 'cbc',
                        })
        resp = self.do_request('list_orders')
        self.assertGreaterEqual(len(resp['orders']), 1)

    def test_create_order(self):
        self.do_request('create_order', cleanup='order',
                        name='create_order', type='key',
                        meta={
                            'name': 'create_orders_s',
                            'algorithm': 'aes',
                            'bit_length': 256,
                            'mode': 'cbc',
                        })

    def test_get_order(self):
        resp = self.do_request('create_order', cleanup='order',
                               name='get_order', type='key',
                               meta={
                                   'name': 'get_order_s',
                                   'algorithm': 'aes',
                                   'bit_length': 256,
                                   'mode': 'cbc',
                               })
        order_id = self.ref_to_uuid(resp['order_ref'])
        resp = self.do_request('get_order', order_id=order_id)
        self.assertEqual(order_id, self.ref_to_uuid(resp['order_ref']))

    def test_delete_order(self):
        resp = self.do_request('create_order',
                               name='delete_order', type='key',
                               meta={
                                   'name': 'delete_order_s',
                                   'algorithm': 'aes',
                                   'bit_length': 256,
                                   'mode': 'cbc',
                               })
        order_id = self.ref_to_uuid(resp['order_ref'])
        while True:
            time.sleep(1)
            resp = self.do_request('get_order', order_id=order_id)
            if 'ACTIVE' == resp['status']:
                self.add_cleanup('secret', resp)
                break

        self.do_request('delete_order', order_id=order_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.OrderClient()


class ProjectReaderTests(base.BarbicanV1RbacBase, BarbicanV1RbacOrders):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.OrderClient()

    def test_list_orders(self):
        self.do_request('list_orders', expected_status=exceptions.Forbidden)

    def test_create_order(self):
        self.do_request('create_order',
                        expected_status=exceptions.Forbidden,
                        cleanup='order',
                        name='create_order', type='key',
                        meta={
                            'name': 'create_orders_s',
                            'algorithm': 'aes',
                            'bit_length': 256,
                            'mode': 'cbc',
                        })

    def test_get_order(self):
        resp = self.do_request(
            'create_order',
            client=self.os_project_member.secret_v1.OrderClient(),
            cleanup='order',
            name='get_order', type='key',
            meta={
                'name': 'get_order_s',
                'algorithm': 'aes',
                'bit_length': 256,
                'mode': 'cbc',
            }
        )
        order_id = self.ref_to_uuid(resp['order_ref'])
        self.do_request('get_order', expected_status=exceptions.Forbidden,
                        order_id=order_id)

    def test_delete_order(self):
        resp = self.do_request(
            'create_order',
            client=self.os_project_member.secret_v1.OrderClient(),
            cleanup='order',
            name='delete_order', type='key',
            meta={
                'name': 'delete_order_s',
                'algorithm': 'aes',
                'bit_length': 256,
                'mode': 'cbc',
            })
        order_id = self.ref_to_uuid(resp['order_ref'])
        self.do_request('delete_order', expected_status=exceptions.Forbidden,
                        order_id=order_id)
