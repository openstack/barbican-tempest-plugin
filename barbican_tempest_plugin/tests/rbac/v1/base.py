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

import base64
from datetime import datetime
from datetime import timedelta
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tempest import clients
from tempest import config
from tempest.lib import auth
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest import test


CONF = config.CONF

RESOURCE_TYPES = ['container', 'order', 'quota', 'secret']


def create_aes_key():
    password = b"password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=1000, backend=default_backend()
    )
    return base64.b64encode(kdf.derive(password))


class BarbicanV1RbacBase(test.BaseTestCase,
                         api_version_utils.BaseMicroversionTest):

    identity_version = 'v3'
    _created_projects = None
    _created_users = None
    created_objects = {}

    credentials = [
        'system_admin',
        'project_alt_member'
    ]

    # TODO(dmendiza): remove this and use the clients instead
    @classmethod
    def ref_to_uuid(cls, href):
        return href.split('/')[-1]

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.enforce_scope.barbican:
            raise cls.skipException("enforce_scope is not enabled for "
                                    "barbican, skipping RBAC tests")
        api_version_utils.check_skip_with_microversion(
            cls.min_microversion,
            cls.max_microversion,
            CONF.key_manager.min_microversion,
            CONF.key_manager.max_microversion)

    @classmethod
    def setup_credentials(cls):
        super().setup_credentials()
        cls._created_projects = list()
        cls._created_users = list()
        project_id = cls.os_system_admin.projects_client.create_project(
            data_utils.rand_name()
        )['project']['id']
        cls._created_projects.append(project_id)
        cls.os_project_admin = cls._setup_new_user_client(project_id, 'admin')
        cls.os_project_member = cls._setup_new_user_client(project_id,
                                                           'member')
        cls.os_project_other_member = cls._setup_new_user_client(project_id,
                                                                 'member')
        cls.os_project_reader = cls._setup_new_user_client(project_id,
                                                           'reader')

    @classmethod
    def _setup_new_user_client(cls, project_id, role):
        """Create a new tempest.clients.Manager

        Creates a new user with the given roles on the given project,
        and returns an instance of tempest.clients.Manager set up
        for that user.

        Users are cleaned up during class teardown in cls.clear_credentials
        """
        user = {
            'name': data_utils.rand_name('user'),
            'password': data_utils.rand_password()
        }
        user_id = cls.os_system_admin.users_v3_client.create_user(
            **user
        )['user']['id']
        cls._created_users.append(user_id)
        role_id = cls.os_system_admin.roles_v3_client.list_roles(
            name=role
        )['roles'][0]['id']
        cls.os_system_admin.roles_v3_client.create_user_role_on_project(
            project_id, user_id, role_id
        )
        creds = auth.KeystoneV3Credentials(
            user_id=user_id,
            password=user['password'],
            project_id=project_id
        )
        auth_provider = clients.get_auth_provider(creds)
        creds = auth_provider.fill_credentials()
        return clients.Manager(credentials=creds)

    @classmethod
    def clear_credentials(cls):
        for user_id in cls._created_users:
            cls.os_system_admin.users_v3_client.delete_user(user_id)
        for project_id in cls._created_projects:
            cls.os_system_admin.projects_client.delete_project(project_id)
        super().clear_credentials()

    @classmethod
    def setup_clients(cls):
        super().setup_clients()

        # setup clients for admin persona
        adm = cls.os_project_admin
        cls.admin_secret_client = adm.secret_v1.SecretClient()
        cls.admin_secret_metadata_client = adm.secret_v1.SecretMetadataClient()
        cls.admin_consumer_client = adm.secret_v1.ConsumerClient()
        cls.admin_secret_consumer_client = \
            adm.secret_v1_1.SecretConsumerClient()
        cls.admin_container_client = adm.secret_v1.ContainerClient()
        cls.admin_order_client = adm.secret_v1.OrderClient(
            secret_client=cls.admin_secret_client,
            container_client=cls.admin_container_client
        )
        cls.admin_quota_client = adm.secret_v1.QuotaClient()

        # set clients for member persona
        member = cls.os_project_member
        cls.secret_client = member.secret_v1.SecretClient()
        cls.secret_metadata_client = member.secret_v1.SecretMetadataClient()
        cls.member_consumer_client = member.secret_v1.ConsumerClient()
        cls.member_secret_consumer_client = \
            member.secret_v1_1.SecretConsumerClient()
        cls.container_client = member.secret_v1.ContainerClient()
        cls.order_client = member.secret_v1.OrderClient(
            secret_client=cls.secret_client,
            container_client=cls.container_client
        )
        cls.quota_client = member.secret_v1.QuotaClient()

        # set up clients for member persona associated with a different
        # project
        cls.other_secret_client = \
            cls.os_project_alt_member.secret_v1.SecretClient()
        cls.other_secret_metadata_client = \
            cls.os_project_alt_member.secret_v1.SecretMetadataClient()
        cls.other_container_client = \
            cls.os_project_alt_member.secret_v1.ContainerClient()
        cls.other_order_client = \
            cls.os_project_alt_member.secret_v1.OrderClient(
                secret_client=cls.other_secret_client,
                container_client=cls.other_container_client
            )

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
            for quota_uuid in list(cls.created_objects['quota']):
                cls.admin_quota_client.delete_project_quota(quota_uuid)
                cls.created_objects['quota'].remove(quota_uuid)
            for secret_uuid in list(cls.created_objects['secret']):
                cls.admin_secret_client.delete_secret(secret_uuid)
                cls.created_objects['secret'].remove(secret_uuid)

            for client in [cls.secret_client,
                           cls.order_client,
                           cls.admin_secret_client,
                           cls.admin_order_client,
                           cls.other_secret_client,
                           cls.other_order_client]:
                client.cleanup()
        finally:
            super(BarbicanV1RbacBase, cls).resource_cleanup()

    @classmethod
    def add_cleanup(cls, resource, response):
        if resource == 'container':
            uuid = cls.ref_to_uuid(response['container_ref'])
        if resource == 'quota':
            uuid = cls.ref_to_uuid(response['quota_ref'])
        if resource == 'secret':
            uuid = cls.ref_to_uuid(response['secret_ref'])
        cls.created_objects[resource].add(uuid)

    @classmethod
    def delete_cleanup(cls, resource, uuid):
        cls.created_objects[resource].remove(uuid)

    # TODO(dmendiza): get rid of this helper method.
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
            # self.assertEqual(response.response.status, expected_status)
            if cleanup is not None:
                self.add_cleanup(cleanup, response)
            return response

    def create_empty_secret_admin(self, secret_name):
        """add empty secret as admin user """
        return self.admin_secret_client.create_secret(name=secret_name)

    def create_empty_container_admin(self,
                                     container_name,
                                     container_type='generic'):
        """add empty container as admin user"""
        return self.admin_container_client.create_container(
            name=container_name,
            type=container_type)

    def create_aes_secret_admin(self, secret_name):
        key = create_aes_key()
        expire_time = (datetime.utcnow() + timedelta(days=5))
        return key, self.do_request(
            'create_secret', client=self.admin_secret_client,
            expected_status=201, cleanup="secret",
            expiration=expire_time.isoformat(), algorithm="aes",
            bit_length=256, mode="cbc", payload=key,
            payload_content_type="application/octet-stream",
            payload_content_encoding="base64",
            name=secret_name
        )

    def create_other_project_secret(self, secret_name, payload=None):
        kwargs = {
            'name': secret_name,
            'secret_type': 'passphrase',
        }
        if payload is not None:
            kwargs['payload'] = payload
            kwargs['payload_content_type'] = 'text/plain'
        resp = self.other_secret_client.create_secret(**kwargs)
        return self.other_secret_client.ref_to_uuid(resp['secret_ref'])

    def create_test_secret(self, client, name, payload=None):
        """Create a secret for testing

        The new secret is created using the given client.  If no
        payload is given, the secret is left empty.

        :returns: the uuid for the new secret
        """
        kwargs = {
            'name': name,
            'secret_type': 'passphrase'
        }
        if payload is not None:
            kwargs['payload'] = payload
            kwargs['payload_content_type'] = 'text/plain'
        resp = client.create_secret(**kwargs)
        return client.ref_to_uuid(resp['secret_ref'])

    def create_test_order(self, client, order_name):
        """Create a symmetric key order for testing

        The new order is created using the given
        client.

        :returns: the uuid for the new order
        """
        kwargs = {
            'type': 'key',
            'meta': {
                'name': order_name,
                'algorithm': 'AES',
                'bit_length': 256,
                'mode': 'CBC',
            }
        }
        resp = client.create_order(**kwargs)
        return client.ref_to_uuid(resp['order_ref'])

    def create_test_container(self, client, name):
        """Create a generic container for testing

        The new container is created using the given client.

        :returns: the uuid for the new container
        """
        container = {
            "type": "generic",
            "name": name,
        }
        resp = client.create_container(**container)
        return client.ref_to_uuid(resp['container_ref'])
