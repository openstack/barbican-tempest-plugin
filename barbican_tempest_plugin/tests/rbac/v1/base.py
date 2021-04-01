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


class BarbicanV1RbacBase(test.BaseTestCase):

    identity_version = 'v3'
    _created_projects = None
    _created_users = None
    created_objects = {}

    credentials = ['system_admin']

    @classmethod
    def ref_to_uuid(cls, href):
        return href.split('/')[-1]

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if not CONF.barbican_rbac_scope_verification.enforce_scope:
            raise cls.skipException("enforce_scope is not enabled for "
                                    "barbican, skipping RBAC tests")

    @classmethod
    def setup_credentials(cls):
        super().setup_credentials()
        cls._created_projects = list()
        cls._created_users = list()
        project_id = cls.os_system_admin.projects_client.create_project(
            data_utils.rand_name()
        )['project']['id']
        cls._created_projects.append(project_id)
        setattr(cls, 'os_project_admin',
                cls._setup_new_user_client(project_id, 'admin'))
        setattr(cls, 'os_project_member',
                cls._setup_new_user_client(project_id, 'member'))
        setattr(cls, 'os_project_reader',
                cls._setup_new_user_client(project_id, 'reader'))

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

        # setup clients for primary persona
        os = cls.os_project_member
        cls.secret_client = os.secret_v1.SecretClient()
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )
        cls.consumer_client = os.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.container_client = os.secret_v1.ContainerClient()
        cls.order_client = os.secret_v1.OrderClient()
        cls.quota_client = os.secret_v1.QuotaClient()
        cls.secret_client = os.secret_v1.SecretClient()
        cls.secret_metadata_client = os.secret_v1.SecretMetadataClient(
            service='key-manager'
        )

        # setup clients for admin persona
        # this client is used for any cleanupi/setup etc. as needed
        adm = cls.os_project_admin
        cls.admin_secret_client = adm.secret_v1.SecretClient()
        cls.admin_secret_metadata_client = adm.secret_v1.SecretMetadataClient(
            service='key-manager'
        )
        cls.admin_consumer_client = adm.secret_v1.ConsumerClient(
            service='key-manager'
        )
        cls.admin_container_client = adm.secret_v1.ContainerClient()
        cls.admin_order_client = adm.secret_v1.OrderClient()
        cls.admin_quota_client = adm.secret_v1.QuotaClient()
        cls.admin_secret_client = adm.secret_v1.SecretClient(
            service='key-manager'
        )
        cls.admin_secret_metadata_client = adm.secret_v1.SecretMetadataClient(
            service='key-manager'
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
            uuid = cls.ref_to_uuid(response['container_ref'])
        if resource == 'order':
            uuid = cls.ref_to_uuid(response.get('order_ref'))
            order_metadata = cls.admin_order_client.get_order(uuid)
            secret_ref = order_metadata.get('secret_ref')
            if secret_ref:
                cls.created_objects['secret'].add(cls.ref_to_uuid(secret_ref))
            uuid = cls.ref_to_uuid(response['order_ref'])
        if resource == 'quota':
            uuid = cls.ref_to_uuid(response['quota_ref'])
        if resource == 'secret':
            uuid = cls.ref_to_uuid(response['secret_ref'])
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
            # self.assertEqual(response.response.status, expected_status)
            if cleanup is not None:
                self.add_cleanup(cleanup, response)
            return response

    def create_empty_secret_admin(self, secret_name):
        """add empty secret as admin user """
        return self.do_request(
            'create_secret', client=self.admin_secret_client,
            expected_status=201, cleanup='secret', name=secret_name)

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
