# Copyright 2016 SAP SE
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

import functools

from tempest import config
from tempest import test

from barbican_tempest_plugin import clients

CONF = config.CONF

# NOTE(dane-fichter): We need to track resource types for cleanup.
RESOURCE_TYPES = ['container', 'order', 'quota', 'secret']


def _get_uuid(href):
    return href.split('/')[-1]


def creates(resource):
    """Decorator that adds resource UUIDs to queue for cleanup"""

    def decorator(f):
        @functools.wraps(f)
        def wrapper(cls, *args, **kwargs):
            resp = f(cls, *args, **kwargs)
            if resource == 'container':
                uuid = _get_uuid(resp['container_ref'])
            if resource == 'order':
                uuid = _get_uuid(resp.get('order_ref'))
                order_metadata = cls.get_order(uuid)
                secret_ref = order_metadata.get('secret_ref')
                if secret_ref:
                    cls.created_objects['secret'].add(_get_uuid(secret_ref))
                uuid = _get_uuid(resp['order_ref'])
            if resource == 'quota':
                uuid = _get_uuid(args[0])
            if resource == 'secret':
                uuid = _get_uuid(resp['secret_ref'])
            cls.created_objects[resource].add(uuid)
            return resp
        return wrapper
    return decorator


class BaseKeyManagerTest(test.BaseTestCase):
    """Base class for all api tests."""

    # Why do I have to be an admin to create secrets? No idea...
    credentials = ('admin', ['service_admin', 'key-manager:service-admin'])
    client_manager = clients.Clients
    created_objects = {}

    @classmethod
    def setup_clients(cls):
        super(BaseKeyManagerTest, cls).setup_clients()
        os = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.consumer_client = os.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.container_client = os.secret_v1.ContainerClient(
            service='key-manager'
        )
        cls.order_client = os.secret_v1.OrderClient(service='key-manager')
        cls.secret_client = os.secret_v1.SecretClient(service='key-manager')
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )

        os = getattr(cls, 'os_roles_%s' % cls.credentials[1][0])
        cls.quota_client = os.secret_v1.QuotaClient(service='key-manager')

    @classmethod
    def setup_credentials(cls):
        super().setup_credentials()
        cls.os_primary = getattr(cls, f'os_{cls.credentials[0]}')

    @classmethod
    def resource_setup(cls):
        super(BaseKeyManagerTest, cls).resource_setup()
        for resource in RESOURCE_TYPES:
            cls.created_objects[resource] = set()

    @classmethod
    def resource_cleanup(cls):
        try:
            for container_uuid in list(cls.created_objects['container']):
                cls.delete_container(container_uuid)
            for order_uuid in list(cls.created_objects['order']):
                cls.delete_order(order_uuid)
            for project_quota_uuid in list(cls.created_objects['quota']):
                cls.delete_project_quota(project_quota_uuid)
            for secret_uuid in list(cls.created_objects['secret']):
                cls.delete_secret(secret_uuid)
        finally:
            super(BaseKeyManagerTest, cls).resource_cleanup()

    @classmethod
    @creates('container')
    def create_container(cls, **kwargs):
        return cls.container_client.create_container(**kwargs)

    @classmethod
    def delete_container(cls, uuid):
        cls.created_objects['container'].remove(uuid)
        return cls.container_client.delete_container(uuid)

    @classmethod
    @creates('order')
    def create_order(cls, **kwargs):
        return cls.order_client.create_order(**kwargs)

    @classmethod
    def get_order(cls, uuid):
        return cls.order_client.get_order(uuid)

    @classmethod
    def delete_order(cls, uuid):
        cls.created_objects['order'].remove(uuid)
        return cls.order_client.delete_order(uuid)

    @classmethod
    @creates('quota')
    def create_project_quota(cls, project_id, **kwargs):
        return cls.quota_client.create_project_quota(project_id, **kwargs)

    @classmethod
    def delete_project_quota(cls, project_id):
        cls.created_objects['quota'].remove(project_id)
        return cls.quota_client.delete_project_quota(project_id)

    @classmethod
    @creates('secret')
    def create_secret(cls, **kwargs):
        return cls.secret_client.create_secret(**kwargs)

    @classmethod
    def delete_secret(cls, uuid):
        cls.created_objects['secret'].remove(uuid)
        return cls.secret_client.delete_secret(uuid)
