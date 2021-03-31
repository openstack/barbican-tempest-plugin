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
        Thist test must check:
          * whether the persona can create a new container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_container(self):
        """Test get_container policy

        Testing: GET /v1/containers/{container-id}
        Thist test must check:
          * whether the persona can get a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_container(self):
        """Test delete_container policy

        Testing: DELETE /v1/containers/{container-id}
        Thist test must check:
          * whether the persona can delete a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_add_secret_to_container(self):
        """Test add_secret_to_container policy

        Testing: POST /v1/containers/{container-id}/secrets
        Thist test must check:
          * whether the persona can add a secret to a container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_secret_from_container(self):
        """Test delete_secret_from_container policy

        Testing: DELETE /v1/containers/{container-id}/secrets
        Thist test must check:
          * whether the persona can delete a secret from a container
        """
        raise NotImplementedError


class ProjectMemberTests(base.BarbicanV1RbacBase, BarbicanV1RbacContainers):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.ContainerClient()
        cls.secret_client = cls.os_project_member.secret_v1.SecretClient()

    def test_list_containers(self):
        self.do_request('create_container', cleanup='container',
                        name='list_containers', type='generic')

        resp = self.do_request('list_containers')
        containers = resp['containers']

        self.assertGreaterEqual(len(containers), 1)

    def test_create_container(self):
        self.do_request('create_container', cleanup='container',
                        name='create_container', type='generic')

    def test_get_container(self):
        resp = self.do_request('create_container', cleanup='container',
                               name='get_container', type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request('get_container', container_id=container_id)

        self.assertEqual(container_id, self.ref_to_uuid(resp['container_ref']))

    def test_delete_container(self):
        resp = self.do_request('create_container', name='delete_container',
                               type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request('delete_container', container_id=container_id)

    def test_add_secret_to_container(self):
        resp = self.do_request('create_container', cleanup='container',
                               name='add_secret_to_container_c',
                               type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request(
            'create_secret',
            client=self.secret_client,
            cleanup='secret',
            name='add_secret_to_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain'
        )
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        resp = self.do_request('add_secret_to_container',
                               container_id=container_id,
                               secret_id=secret_id)

    def test_delete_secret_from_container(self):
        resp = self.do_request('create_container', cleanup='container',
                               name='delete_secret_from_container_c',
                               type='generic')
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request(
            'create_secret',
            client=self.secret_client,
            cleanup='secret',
            name='delete_secret_from_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain'
        )
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.do_request('add_secret_to_container',
                        container_id=container_id,
                        secret_id=secret_id)
        resp = self.do_request('delete_secret_from_container',
                               container_id=container_id,
                               secret_id=secret_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.ContainerClient()
        cls.secret_client = cls.os_project_admin.secret_v1.SecretClient()


class ProjectReaderTests(base.BarbicanV1RbacBase, BarbicanV1RbacContainers):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.ContainerClient()

    def test_list_containers(self):
        self.do_request('list_containers',
                        expected_status=exceptions.Forbidden)

    def test_create_container(self):
        self.do_request('create_container',
                        expected_status=exceptions.Forbidden,
                        name='create_container',
                        type='generic')

    def test_get_container(self):
        resp = self.do_request(
            'create_container',
            client=self.os_project_member.secret_v1.ContainerClient(),
            cleanup='container',
            name='create_container', type='generic'
        )
        container_id = self.ref_to_uuid(resp['container_ref'])

        self.do_request('get_container', expected_status=exceptions.Forbidden,
                        container_id=container_id)

    def test_delete_container(self):
        resp = self.do_request(
            'create_container',
            client=self.os_project_member.secret_v1.ContainerClient(),
            cleanup='container',
            name='delete_container', type='generic'
        )
        container_id = self.ref_to_uuid(resp['container_ref'])

        self.do_request('delete_container',
                        expected_status=exceptions.Forbidden,
                        container_id=container_id)

    def test_add_secret_to_container(self):
        resp = self.do_request(
            'create_container',
            client=self.os_project_member.secret_v1.ContainerClient(),
            cleanup='container',
            name='add_secret_to_container_c', type='generic'
        )
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request(
            'create_secret',
            client=self.os_project_member.secret_v1.SecretClient(),
            cleanup='secret',
            name='add_secret_to_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain'
        )
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.do_request('add_secret_to_container',
                        expected_status=exceptions.Forbidden,
                        container_id=container_id,
                        secret_id=secret_id)

    def test_delete_secret_from_container(self):
        resp = self.do_request(
            'create_container',
            client=self.os_project_member.secret_v1.ContainerClient(),
            cleanup='container',
            name='delete_secret_from_container_c', type='generic'
        )
        container_id = self.ref_to_uuid(resp['container_ref'])

        resp = self.do_request(
            'create_secret',
            client=self.os_project_member.secret_v1.SecretClient(),
            cleanup='secret',
            name='delete_secret_from_container_s',
            secret_type='passphrase',
            payload='shhh... secret',
            payload_content_type='text/plain'
        )
        secret_id = self.ref_to_uuid(resp['secret_ref'])

        self.do_request(
            'add_secret_to_container',
            client=self.os_project_member.secret_v1.ContainerClient(),
            container_id=container_id,
            secret_id=secret_id
        )

        self.do_request('delete_secret_from_container',
                        expected_status=exceptions.Forbidden,
                        container_id=container_id,
                        secret_id=secret_id)
