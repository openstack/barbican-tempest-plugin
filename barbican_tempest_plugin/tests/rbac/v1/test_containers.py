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
from tempest.lib.common.utils import data_utils
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
        """Test GET /v1/containers/{container-id}/acl

        This test must check:
          * whether the persona can get a containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_update_container_acl(self):
        """Test PATCH /v1/containers/{container-id}/acl

        This test must check:
          * whether the persona can update an existing containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_create_container_acl(self):
        """Test PUT /v1/containers/{container-id}/acl

        This test must check:
          * whether the persona can create a containers acl
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_delete_container_acl(self):
        """Test DELETE /v1/containers/{container-id}/acl

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
    def test_delete_container_consumer(self):
        """Test delete_container_consumer policy

        Testing: DELETE /v1/containers/{container-id}/consumers
        This test must check:
          * whether the persona can delete a consumer of the container
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_container_consumer(self):
        """Test GET /v1/containers/{container-id}/consumers/{consumer-id}

        This test must check:
          * whether the persona can get a containers consumer by id

        NOTE: This route is undocumented, also there's no way to get a
        consumer-id back from the API.
        """
        pass

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
        cls.consumer_client = cls.os_project_reader.secret_v1.ConsumerClient()

    def setUp(self):
        super().setUp()
        self.secret_id = self.create_test_secret(
            self.secret_client,
            data_utils.rand_name('test-containers'),
            'SECRET_PASSPHRASE'
        )
        self.container_id = self.create_test_container(
            self.container_client,
            data_utils.rand_name('test-containers'))
        self.valid_acl = {
            'read': {
                'users': [self.other_secret_client.user_id],
                'project-access': True
            }
        }
        self.test_consumer = {
            "name": "test-consumer",
            "URL": "https://example.test/consumer"
        }
        self.member_consumer_client.add_consumer_to_container(
            self.container_id,
            **self.test_consumer
        )

    def test_list_containers(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.list_containers)

    def test_create_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_container)

    def test_get_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_container,
            container_id=self.container_id)

    def test_delete_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_container,
            container_id=self.container_id)

    def test_get_container_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_container_acl,
            self.container_id)

    def test_update_container_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.patch_container_acl,
            self.container_id,
            self.valid_acl)

    def test_create_container_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.put_container_acl,
            self.container_id,
            self.valid_acl)

    def test_delete_container_acl(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_container,
            self.container_id)

    def test_list_container_consumers(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.consumer_client.list_consumers_in_container,
            self.container_id)

    def test_create_container_consumer(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.consumer_client.add_consumer_to_container,
            self.container_id,
            **self.test_consumer)

    def test_delete_container_consumer(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.consumer_client.delete_consumer_from_container,
            self.container_id,
            **self.test_consumer)

    def test_add_secret_to_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.add_secret_to_container,
            container_id=self.container_id,
            secret_id=self.secret_id)

    def test_delete_secret_from_container(self):
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_secret_from_container,
            container_id=self.container_id,
            secret_id=self.secret_id)


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.container_client
        cls.consumer_client = cls.member_consumer_client

    def test_list_containers(self):
        resp = self.client.list_containers()
        containers = resp['containers']

        self.assertGreaterEqual(len(containers), 1)

    def test_create_container(self):
        container_id = self.create_test_container(
            self.client,
            'test-create-container')

        _ = self.container_client.get_container(container_id)

    def test_get_container(self):
        resp = self.client.get_container(self.container_id)

        self.assertEqual(
            self.container_id,
            self.client.ref_to_uuid(resp['container_ref']))

    def test_delete_container(self):
        self.client.delete_container(self.container_id)

        resp = self.container_client.list_containers()
        container_ids = [self.client.ref_to_uuid(c['container_ref'])
                         for c in resp['containers']]
        self.assertNotIn(self.container_id, container_ids)

    def test_add_secret_to_container(self):
        self.client.add_secret_to_container(
            container_id=self.container_id,
            secret_id=self.secret_id)

        resp = self.client.get_container(self.container_id)
        secret_ids = [self.client.ref_to_uuid(sr['secret_ref'])
                      for sr in resp['secret_refs']]
        self.assertIn(self.secret_id, secret_ids)

    def test_delete_secret_from_container(self):
        self.client.add_secret_to_container(
            self.container_id,
            self.secret_id)
        resp = self.client.get_container(self.container_id)
        secret_ids = [self.client.ref_to_uuid(sr['secret_ref'])
                      for sr in resp['secret_refs']]
        self.assertIn(self.secret_id, secret_ids)

        self.client.delete_secret_from_container(
            self.container_id,
            self.secret_id)

        resp = self.client.get_container(self.container_id)
        secret_ids = [self.client.ref_to_uuid(sr['secret_ref'])
                      for sr in resp['secret_refs']]
        self.assertNotIn(self.secret_id, secret_ids)

    def test_get_container_acl(self):
        resp = self.client.get_container_acl(self.container_id)
        self.assertIn('read', resp.keys())

    def test_create_container_acl(self):
        _ = self.client.put_container_acl(self.container_id, self.valid_acl)

        acl = self.client.get_container_acl(self.container_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])

    def test_update_container_acl(self):
        _ = self.client.put_container_acl(self.container_id, self.valid_acl)
        acl = self.client.get_container_acl(self.container_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])
        clear_users_acl = {
            'read': {
                'users': []
            }
        }

        _ = self.client.patch_container_acl(self.container_id, clear_users_acl)

        acl = self.client.get_container_acl(self.container_id)
        self.assertNotIn(self.other_secret_client.user_id,
                         acl['read']['users'])

    def test_delete_container_acl(self):
        _ = self.client.put_container_acl(self.container_id, self.valid_acl)
        acl = self.client.get_container_acl(self.container_id)
        self.assertIn(self.other_secret_client.user_id, acl['read']['users'])

        _ = self.client.delete_container_acl(self.container_id)

        acl = self.client.get_container_acl(self.container_id)
        self.assertNotIn('users', acl['read'].keys())

    def test_list_container_consumers(self):
        resp = self.consumer_client.list_consumers_in_container(
            self.container_id
        )
        self.assertEqual(1, resp['total'])

    def test_create_container_consumer(self):
        second_consumer = {
            'name': 'another-test-consumer',
            'URL': 'https://exlample.test/consumer/two'
        }

        resp = self.consumer_client.add_consumer_to_container(
            self.container_id,
            **second_consumer)

        self.assertEqual(2, len(resp['consumers']))

    def test_delete_container_consumer(self):
        resp = self.consumer_client.delete_consumer_from_container(
            self.container_id,
            **self.test_consumer)

        self.assertEqual(0, len(resp['consumers']))


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.admin_container_client
        cls.consumer_client = cls.admin_consumer_client


class ProjectReaderTestsAcrossProjects(ProjectReaderTests):
    """Tests for Project Reader across Projects

    Tests for Project Reader Persona using containers/secrets
    that belong to a different project.

    This class overrides setUp to create self.secret_id and
    self.container_id to use objects that belong to a different
    project.

    We re-use most of the tests in ProjectReaderTests because
    we also expect these to be Forbidden.

    The only exception is the two tests we've overridden to
    pass because it is not possible to list or create containers
    on a different project.
    """

    def setUp(self):
        super().setUp()
        self.secret_id = self.create_test_secret(
            self.other_secret_client,
            data_utils.rand_name('test-containers'),
            'SECRET_PASSPHRASE'
        )
        self.container_id = self.create_test_container(
            self.other_container_client,
            data_utils.rand_name('test-containers'))

    def test_list_containers(self):
        """This is not possible across projects"""
        pass

    def test_create_container(self):
        """This is not possible across projects"""
        pass


class ProjectMemberTestsAcrossProjects(ProjectReaderTestsAcrossProjects):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.container_client


class ProjectAdminTestsAcrossProjects(ProjectMemberTestsAcrossProjects):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.admin_container_client
