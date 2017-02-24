# Copyright (c) 2016 Johns Hopkins University Applied Physics Laboratory
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest.lib import decorators

from barbican_tempest_plugin.tests.api import base


class OrdersTest(base.BaseKeyManagerTest):
    """Orders API tests."""

    @decorators.idempotent_id('077c1729-1950-4e62-a29c-daba4aa186ad')
    def test_create_list_delete_orders(self):
        # Confirm that there are no orders
        body = self.order_client.list_orders()
        self.assertEqual(0, body.get('total'), body)
        self.assertEqual(0, len(body.get('orders')), body)

        # Create some orders
        body = self.create_order(
            type="key",
            meta={
                "name": "order-key-1",
                "algorithm": "AES",
                "bit_length": 256,
                "mode": "cbc",
                "payload_content_type": "application/octet-stream"
            }
        )
        order_id_1 = base._get_uuid(body.get('order_ref'))
        body = self.create_order(
            type="key",
            meta={
                "name": "order-key-2",
                "algorithm": "AES",
                "bit_length": 256,
                "mode": "cbc",
                "payload_content_type": "application/octet-stream"
            }
        )
        order_id_2 = base._get_uuid(body.get('order_ref'))

        # Verify that the orders can be found via generic listing.
        body = self.order_client.list_orders()
        self.assertEqual(2, body.get('total'), body)
        self.assertEqual(2, len(body.get('orders')), body)

        orders = body.get('orders')
        for order in orders:
            self.assertIn(
                base._get_uuid(order.get('order_ref')),
                [order_id_1, order_id_2],
                body
            )
            self.assertIn(
                'secret_ref',
                order.keys()
            )

        # Verify that the orders can be found via specific listing.
        body = self.order_client.get_order(order_id_1)
        self.assertEqual(
            order_id_1,
            base._get_uuid(body.get('order_ref')),
            body
        )
        self.assertIn('created', body, body)
        self.assertIn('creator_id', body, body)
        self.assertIn('meta', body, body)

        meta = body.get('meta')
        self.assertEqual("order-key-1", meta.get('name'), meta)
        self.assertEqual("AES", meta.get('algorithm'), meta)
        self.assertEqual(256, meta.get('bit_length'), meta)
        self.assertEqual("cbc", meta.get('mode'), meta)
        self.assertEqual(
            "application/octet-stream",
            meta.get('payload_content_type'),
            meta
        )

        self.assertIn('secret_ref', body, body)
        self.assertEqual("ACTIVE", body.get('status'), body)
        self.assertEqual("key", body.get('type'), body)
        self.assertIn('updated', body, body)

        body = self.order_client.get_order(order_id_2)
        self.assertEqual(
            order_id_2,
            base._get_uuid(body.get('order_ref')),
            body
        )
        self.assertIn('created', body, body)
        self.assertIn('creator_id', body, body)
        self.assertIn('meta', body, body)

        meta = body.get('meta')
        self.assertEqual("order-key-2", meta.get('name'), meta)
        self.assertEqual("AES", meta.get('algorithm'), meta)
        self.assertEqual(256, meta.get('bit_length'), meta)
        self.assertEqual("cbc", meta.get('mode'), meta)
        self.assertEqual(
            "application/octet-stream",
            meta.get('payload_content_type'),
            meta
        )

        self.assertIn('secret_ref', body, body)
        self.assertEqual("ACTIVE", body.get('status'), body)
        self.assertEqual("key", body.get('type'), body)
        self.assertIn('updated', body, body)

        # Delete one order and confirm that it got deleted
        self.delete_order(order_id_1)

        body = self.order_client.list_orders()
        self.assertEqual(1, body.get('total'), body)
        self.assertEqual(1, len(body.get('orders')), body)

        order = body.get('orders')[0]
        self.assertEqual(
            order_id_2,
            base._get_uuid(order.get('order_ref')),
            body
        )

        # Leave one order behind to get cleaned up by infra
