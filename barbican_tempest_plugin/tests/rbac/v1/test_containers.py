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
import abc

from tempest import config
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base


CONF = config.CONF


class BarbicanV1RbacContainers:

    @abc.abstractmethod
    def test_list_containers(self):
        """Test list_containers policy

        Testing: GET /v1/containers
        This test must check:
          * whether the persona can list containers
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_container(self):
        """Test create_container policy

        Testing: POST /v1/containers
        This test must check:
          * whether the persona can create a new container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_container(self):
        """Test get_container policy

        Testing: GET /v1/containers/{container-id}
        This test must check:
          * whether the persona can get a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_container(self):
        """Test delete_container policy

        Testing: DELETE /v1/containers/{container-id}
        This test must check:
          * whether the persona can delete a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_container_acl(self):
        """Test get_container_acl policy

        Testing: GET /v1/containers/{container-id}/acl
        This test must check:
          * whether the persona can get a containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_update_container_acl(self):
        """Test update_container_acl policy

        Testing: PATCH /v1/containers/{container-id}/acl
        This test must check:
          * whether the persona can update an existing containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_container_acl(self):
        """Test create_container_acl policy

        Testing: PUT /v1/containers/{container-id}/acl
        This test must check:
          * whether the persona can create a containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_container_acl(self):
        """Test delete_container_acl policy

        Testing: DELETE /v1/containers/{container-id}
        This test must check:
          * whether the persona can delete a containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_list_container_consumers(self):
        """Test list_container_consumers policy

        Testing: GET /v1/containers/{container-id}/consumers
        This test must check:
          * whether the persona can list a containers consumers
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_container_consumer(self):
        """Test create_container_consumer policy

        Testing: POST /v1/containers/{container-id}/consumers
        This test must check:
          * whether the persona can create a consumer of the container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_container_consumer(self):
        """Test get_container_consumer policy

        Testing: GET /v1/containers/{container-id}/consumers/{consumer-id}
        This test must check:
          * whether the persona can get a containers consumer by id
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_container_consumer(self):
        """Test delete_container_consumer policy

        Testing: DELETE /v1/containers/{container-id}/consumers/{consumer-id}
        This test must check:
          * whether the persona can delete a containers consumer by id
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_add_secret_to_container(self):
        """Test add_secret_to_container policy

        Testing: POST /v1/containers/{container-id}/secrets
        This test must check:
          * whether the persona can add a secret to a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret_from_container(self):
        """Test delete_secret_from_container policy

        Testing: DELETE /v1/containers/{container-id}/secrets
        This test must check:
          * whether the persona can delete a secret from a container
        """
        raise NotImplementedError


class ProjectReaderTests(base.BarbicanV1RbacBase, BarbicanV1RbacContainers):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.ContainerClient()
        cls.secret_client = cls.os_project_reader.secret_v1.SecretClient()
        cls.consumer_client = cls.os_project_reader.secret_v1.ConsumerClient(
            service='key-manager')

    def test_list_containers(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.list_containers)

    def test_create_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_container)

    def test_get_container(self):
        resp = self.create_empty_container_admin('test_reader_get_container')
        container_id = self.ref_to_uuid(resp['container_ref'])
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_container,
            container_id=container_id)

    def test_delete_container(self):
        resp = self.create_empty_container_admin(
            'test_reader_delete_container')
        container_id = self.ref_to_uuid(resp['container_ref'])
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_container,
            container_id=container_id)

    def test_get_container_acl(self):
        pass

    def test_update_container_acl(self):
        pass

    def test_create_container_acl(self):
        pass

    def test_delete_container_acl(self):
        pass

    def test_list_container_consumers(self):
        pass

    def test_create_container_consumer(self):
        pass

    def test_get_container_consumer(self):
        pass

    def test_delete_container_consumer(self):
        pass

    def test_add_secret_to_container(self):
        resp = self.create_empty_container_admin(
            'test_reader_add_secret_to_container_container')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.create_empty_secret_admin(
            'test_reader_add_secret_to_container_secret')
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.assertRaises(
            exceptions.Forbidden,
            self.client.add_secret_to_container,
            container_id=container_id,
            secret_id=secret_id)

    def test_delete_secret_from_container(self):
        resp = self.create_empty_container_admin(
            'test_reader_delete_secret_from_container_container')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.create_empty_secret_admin(
            'test_reader_delete_secret_from_container_secret')
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_from_container,
            container_id=container_id,
            secret_id=secret_id)


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.ContainerClient()
        cls.secret_client = cls.os_project_member.secret_v1.SecretClient()
        cls.consumer_client = cls.os_project_member.secret_v1.ConsumerClient()

    def test_list_containers(self):
        self.client.create_container(
            name='test_list_containers',
            type='generic')
        resp = self.client.list_containers(name='test_list_containers')
        containers = resp['containers']

        self.assertGreaterEqual(len(containers), 1)

    def test_create_container(self):
        self.client.create_container(
            name='test_create_containers',
            type='generic')

    def test_get_container(self):
        resp = self.client.create_container(
            name='get_container',
            type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])
        resp = self.client.get_container(container_id=container_id)

        self.assertEqual(container_id, self.ref_to_uuid(resp['container_ref']))

    def test_delete_container(self):
        resp = self.client.create_container(
            name='delete_container',
            type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        self.client.delete_container(container_id)

    def test_add_secret_to_container(self):
        resp = self.client.create_container(
            name='add_secret_to_container_c',
            type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.secret_client.create_secret(
            cleanup='secret',
            name='add_secret_to_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain')

        secret_id = self.ref_to_uuid(resp['secret_ref'])
        self.client.add_secret_to_container(
            container_id=container_id,
            secret_id=secret_id)

    def test_delete_secret_from_container(self):
        resp = self.client.create_container(
            name='add_secret_to_container_c',
            type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.secret_client.create_secret(
            cleanup='secret',
            name='add_secret_to_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain')
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.client.add_secret_to_container(
            container_id=container_id,
            secret_id=secret_id)

        self.client.delete_secret_from_container(
            container_id=container_id,
            secret_id=secret_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.ContainerClient()
        cls.secret_client = cls.os_project_admin.secret_v1.SecretClient()
        cls.consumer_client = cls.os_project_member.secret_v1.ConsumerClient()
