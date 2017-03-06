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


class ConsumersTest(base.BaseKeyManagerTest):
    """Containers API tests."""

    @decorators.idempotent_id('7d46a170-6b3b-4f4d-903a-b29aebb93289')
    def test_add_delete_consumers_in_container(self):
        # Create a container to test against
        body = self.create_container(
            type="generic",
            name="consumer-container"
        )
        container_id = base._get_uuid(body.get('container_ref'))

        # Confirm that the container has no consumers
        body = self.consumer_client.list_consumers_in_container(container_id)
        self.assertEqual(0, body.get('total'), body)
        self.assertEmpty(body.get('consumers'), body)

        # Add some consumers to the container
        body = self.consumer_client.add_consumer_to_container(
            container_id,
            name="consumer1",
            URL="url1"
        )
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual(1, len(body.get('consumers')), body)
        body = self.consumer_client.add_consumer_to_container(
            container_id,
            name="consumer2",
            URL="url2"
        )
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual(2, len(body.get('consumers')), body)

        # Confirm that the consumers are in the container
        body = self.consumer_client.list_consumers_in_container(container_id)
        self.assertEqual(2, body.get('total'), body)
        self.assertEqual(2, len(body.get('consumers')), body)
        for consumer in body.get('consumers'):
            self.assertIn(consumer.get('name'), ("consumer1", "consumer2"))
            self.assertIn(consumer.get('URL'), ("url1", "url2"))

        # Remove the consumers from the container
        body = self.consumer_client.delete_consumer_from_container(
            container_id,
            name="consumer1",
            URL="url1"
        )
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual(1, len(body.get('consumers')), body)
        body = self.consumer_client.delete_consumer_from_container(
            container_id,
            name="consumer2",
            URL="url2"
        )
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual(0, len(body.get('consumers')), body)

        # Confirm that the container has no consumers
        body = self.consumer_client.list_consumers_in_container(container_id)
        self.assertEqual(0, body.get('total'), body)
        self.assertEqual(0, len(body.get('consumers')), body)

        # Clean up the container
        self.delete_container(container_id)
