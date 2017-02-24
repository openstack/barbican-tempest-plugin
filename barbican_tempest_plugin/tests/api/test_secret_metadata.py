# Copyright 2017 Johns Hopkins Applied Physics Lab
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from tempest.lib import decorators

from barbican_tempest_plugin.tests.api import base


class SecretMetadataTest(base.BaseKeyManagerTest):
    """Metadata API test"""
    @decorators.idempotent_id('2b0c1707-afc3-4674-a6c6-4dc42f318117')
    def test_secret_metadata(self):
        # Create a secret
        sec = self.create_secret()
        uuid = base._get_uuid(sec['secret_ref'])

        # Add multiple metadata fields
        self.secret_metadata_client.put_secret_metadata(
            uuid,
            description='contains the AES key',
            geolocation='12.3456, -98.7654'
        )

        metadata = self.secret_metadata_client.get_secret_metadata(uuid)
        self.assertEqual(2, len(metadata.keys()))
        self.assertIn('description', metadata.keys())
        self.assertIn('geolocation', metadata.keys())
        self.assertEqual('contains the AES key', metadata['description'])
        self.assertEqual('12.3456, -98.7654', metadata['geolocation'])

        # Add a single metadata field
        self.secret_metadata_client.create_key_value_pair(
            uuid,
            key='extra',
            value='extra value'
        )
        metadata = self.secret_metadata_client.get_secret_metadata(uuid)
        self.assertEqual(3, len(metadata.keys()))
        self.assertEqual('extra value', metadata['extra'])

        # Modify the metadata field
        self.secret_metadata_client.update_secret_metadata(
            uuid,
            key='extra',
            value='new value'
        )
        metadata = self.secret_metadata_client.get_secret_metadata(uuid)
        self.assertEqual('new value', metadata['extra'])

        # Delete the extra key-value pair
        self.secret_metadata_client.delete_secret_metadata_by_key(
            uuid,
            'extra'
        )
        metadata = self.secret_metadata_client.get_secret_metadata(uuid)
        self.assertEqual(2, len(metadata.keys()))
