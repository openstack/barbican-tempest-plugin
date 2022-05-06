# Copyright (c) 2022 Red Hat Inc.
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


class SecretConsumersTest(base.BaseKeyManagerTest):
    """Secret Consumers API tests."""

    min_microversion = '1.1'

    @decorators.idempotent_id('07a47f8b-e454-4dd0-afb6-bfa12677cd8e')
    def test_add_delete_consumers_in_secret(self):
        # Create a secret to test against
        sec = self.create_secret(name='secret_1')
        secret_id = self.secret_consumer_client.ref_to_uuid(sec['secret_ref'])

        # Confirm that the secret has no consumers
        body = self.secret_consumer_client.list_consumers_in_secret(secret_id)
        self.assertEqual(0, body.get('total'))
        self.assertEmpty(body.get('consumers'))

        # Add some consumers to the secret
        body = self.secret_consumer_client.add_consumer_to_secret(
            secret_id,
            service="service1",
            resource_id="resource_id1",
            resource_type="resource_type1"
        )
        self.assertEqual(
            secret_id,
            self.secret_consumer_client.ref_to_uuid(body.get('secret_ref'))
        )
        self.assertEqual(1, len(body.get('consumers')))
        body = self.secret_consumer_client.add_consumer_to_secret(
            secret_id,
            service="service2",
            resource_id="resource_id2",
            resource_type="resource_type2"
        )
        self.assertEqual(
            secret_id,
            self.secret_consumer_client.ref_to_uuid(body.get('secret_ref'))
        )
        self.assertEqual(2, len(body.get('consumers')))

        # Confirm that the consumers are in the secret
        body = self.secret_consumer_client.list_consumers_in_secret(secret_id)
        self.assertEqual(2, body.get('total'))
        self.assertEqual(2, len(body.get('consumers')))
        for consumer in body.get('consumers'):
            self.assertIn(consumer.get('service'), ("service1", "service2"))
            self.assertIn(consumer.get('resource_id'),
                          ("resource_id1", "resource_id2"))
            self.assertIn(consumer.get('resource_type'),
                          ("resource_type1", "resource_type2"))

        # Remove the consumers from the secret
        body = self.secret_consumer_client.delete_consumer_from_secret(
            secret_id,
            service="service1",
            resource_id="resource_id1",
            resource_type="resource_type1"
        )
        self.assertEqual(
            secret_id,
            self.secret_consumer_client.ref_to_uuid(body.get('secret_ref'))
        )
        self.assertEqual(1, len(body.get('consumers')))
        body = self.secret_consumer_client.delete_consumer_from_secret(
            secret_id,
            service="service2",
            resource_id="resource_id2",
            resource_type="resource_type2"
        )
        self.assertEqual(
            secret_id,
            self.secret_consumer_client.ref_to_uuid(body.get('secret_ref'))
        )
        self.assertEqual(0, len(body.get('consumers')))

        # Confirm that the secret has no consumers
        body = self.secret_consumer_client.list_consumers_in_secret(secret_id)
        self.assertEqual(0, body.get('total'))
        self.assertEqual(0, len(body.get('consumers')))

        # Clean up the secret
        self.delete_secret(secret_id)
