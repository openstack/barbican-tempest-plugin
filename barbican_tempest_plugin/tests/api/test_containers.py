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


class ContainersTest(base.BaseKeyManagerTest):
    """Containers API tests."""

    @decorators.idempotent_id('2e13d4bb-54de-463a-a358-0fb9a221d8f3')
    def test_create_list_delete_empty_container(self):
        # Create a container to test against.
        body = self.create_container(type="generic", name="empty-container")
        container_id = base._get_uuid(body.get('container_ref'))

        # Verify that the container can be found via specific listing.
        body = self.container_client.get_container(container_id)
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual("generic", body.get('type'), body)
        self.assertEqual("empty-container", body.get('name'), body)
        self.assertEqual("ACTIVE", body.get('status'), body)
        self.assertEmpty(body.get('secret_refs'), body)
        self.assertEmpty(body.get('consumers'), body)
        self.assertIn('created', body, body)
        self.assertIn('updated', body, body)
        self.assertIn('creator_id', body, body)

        # Verify that the container can be found via generic listing.
        body = self.container_client.list_containers()
        self.assertEqual(1, body.get('total'), body)
        self.assertEqual(1, len(body.get('containers')), body)

        container = body.get('containers')[0]
        self.assertEqual(
            container_id,
            base._get_uuid(container.get('container_ref')),
            container
        )
        self.assertEqual("generic", container.get('type'), container)
        self.assertEqual("empty-container", container.get('name'), container)
        self.assertEqual("ACTIVE", container.get('status'), container)
        self.assertEmpty(container.get('secret_refs'), container)
        self.assertEmpty(container.get('consumers'), container)
        self.assertIn('created', container, container)
        self.assertIn('updated', container, container)
        self.assertIn('creator_id', container, container)

        # Leave the container behind to get cleaned up by infra.

    @decorators.idempotent_id('af10a78d-b1f8-440d-8b89-639861f16fd0')
    def test_add_to_delete_from_container(self):
        # Create a container to test against.
        body = self.create_container(type="generic", name="test-container")
        container_id = base._get_uuid(body.get('container_ref'))

        # Create some secrets to store in the container
        body = self.create_secret()
        secret1_id = base._get_uuid(body.get('secret_ref'))
        body = self.create_secret()
        secret2_id = base._get_uuid(body.get('secret_ref'))

        # Confirm that the container is empty
        body = self.container_client.get_container(container_id)
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEmpty(body.get('secret_refs'), body)

        # Add the secrets to the container
        self.container_client.add_secret_to_container(
            container_id,
            secret1_id
        )
        self.container_client.add_secret_to_container(
            container_id,
            secret2_id
        )

        # Confirm that the secrets are in the container
        body = self.container_client.get_container(container_id)
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEqual(2, len(body.get('secret_refs')), body)
        for secret_ref in body.get('secret_refs'):
            secret_id = base._get_uuid(secret_ref.get('secret_ref'))
            self.assertIn(secret_id, (secret1_id, secret2_id))

        # Remove the secrets from the container
        self.container_client.delete_secret_from_container(
            container_id,
            secret1_id
        )
        self.container_client.delete_secret_from_container(
            container_id,
            secret2_id
        )

        # Confirm that the container is empty
        body = self.container_client.get_container(container_id)
        self.assertEqual(
            container_id,
            base._get_uuid(body.get('container_ref')),
            body
        )
        self.assertEmpty(body.get('secret_refs'), body)

        # Clean up the containe
        self.delete_container(container_id)
