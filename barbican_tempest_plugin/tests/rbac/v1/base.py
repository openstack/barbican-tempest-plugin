# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tempest import config

CONF = config.CONF

RESOURCE_TYPES = ['container', 'order', 'quota', 'secret']


def _get_uuid(href):
    return href.split('/')[-1]


class BarbicanV1RbacBase(object):

    identity_version = 'v3'
    created_objects = {}

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.barbican_rbac_scope_verification.enforce_scope:
            raise cls.skipException("enforce_scope is not enabled for "
                                    "barbican, skipping RBAC tests")

    @classmethod
    def setup_clients(cls):
        super().setup_clients()

        # setup clients for primary persona
        os = getattr(cls, f'os_{cls.credentials[0]}')
        cls.secret_client = os.secret_v1.SecretClient(service='key-manager')
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )
        cls.consumer_client = os.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.container_client = os.secret_v1.ContainerClient(
            service='key-manager'
        )
        cls.order_client = os.secret_v1.OrderClient(service='key-manager')
        cls.quota_client = os.secret_v1.QuotaClient(service='key-manager')
        cls.secret_client = os.secret_v1.SecretClient(service='key-manager')
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )

        # setup clients for admin persona
        # this client is used for any cleanupi/setup etc. as needed
        adm = getattr(cls, f'os_{cls.credentials[1]}')
        cls.admin_secret_client = adm.secret_v1.SecretClient(
            service='key-manager')
        cls.admin_secret_metadata_client = adm.secret_v1.SecretMetadataClient(
            service='key-manager'
        )
        cls.admin_consumer_client = adm.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.admin_container_client = adm.secret_v1.ContainerClient(
            service='key-manager'
        )
        cls.admin_order_client = adm.secret_v1.OrderClient(
            service='key-manager'
        )
        cls.admin_quota_client = adm.secret_v1.QuotaClient(
            service='key-manager'
        )
        cls.admin_secret_client = adm.secret_v1.SecretClient(
            service='key-manager'
        )
        cls.admin_secret_metadata_client = adm.secret_v1.SecretMetadataClient(
            service='key-manager'
        )

    @classmethod
    def setup_credentials(cls):
        super().setup_credentials()
        cls.os_primary = getattr(cls, f'os_{cls.credentials[0]}')

    @classmethod
    def resource_setup(cls):
        super().resource_setup()
        for resource in RESOURCE_TYPES:
            cls.created_objects[resource] = set()

    @classmethod
    def resource_cleanup(cls):
        try:
            for container_uuid in list(cls.created_objects['container']):
                cls.admin_container_client.delete_container(container_uuid)
                cls.created_objects['container'].remove(container_uuid)
            for order_uuid in list(cls.created_objects['order']):
                cls.admin_order_client.delete_order(order_uuid)
                cls.created_objects['order'].remove(order_uuid)
            for quota_uuid in list(cls.created_objects['quota']):
                cls.admin_quota_client.delete_project_quota(quota_uuid)
                cls.created_objects['quota'].remove(quota_uuid)
            for secret_uuid in list(cls.created_objects['secret']):
                cls.admin_secret_client.delete_secret(secret_uuid)
                cls.created_objects['secret'].remove(secret_uuid)
        finally:
            super(BarbicanV1RbacBase, cls).resource_cleanup()

    @classmethod
    def add_cleanup(cls, resource, response):
        if resource == 'container':
            uuid = _get_uuid(response['container_ref'])
        if resource == 'order':
            uuid = _get_uuid(response.get('order_ref'))
            order_metadata = cls.get_order(uuid)
            secret_ref = order_metadata.get('secret_ref')
            if secret_ref:
                cls.created_objects['secret'].add(_get_uuid(secret_ref))
            uuid = _get_uuid(response['order_ref'])
        if resource == 'quota':
            uuid = _get_uuid(response['quota_ref'])
        if resource == 'secret':
            uuid = _get_uuid(response['secret_ref'])
        cls.created_objects[resource].add(uuid)

    @classmethod
    def delete_cleanup(cls, resource, uuid):
        cls.created_objects[resource].remove(uuid)

    def do_request(self, method, client=None, expected_status=200,
                   cleanup=None, **args):
        if client is None:
            client = self.client
        if isinstance(expected_status, type(Exception)):
            self.assertRaises(expected_status,
                              getattr(client, method),
                              **args)
        else:
            response = getattr(client, method)(**args)
            self.assertEqual(response.response.status, expected_status)
            if cleanup is not None:
                self.add_cleanup(cleanup, response)
            return response
