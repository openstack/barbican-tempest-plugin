# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import abc

from tempest.lib import decorators
from tempest.lib import exceptions

from barbican_tempest_plugin.tests.rbac.v1 import base


class BarbicanV1RbacQuota:

    @abc.abstractmethod
    def test_get_effective_project_quota(self):
        """Test getting the effective quota information

        Testing: GET /v1/quotas
        This test must check:
          * whether the persona can retrieve the effective quota for
            their project.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_list_project_quotas(self):
        """Test listing all configured project quotas

        Testing: GET /v1/project-quotas
        This test must check:
          * whether the persona can retrieve all modified quotas for
            the entire system.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_custom_quota_for_project(self):
        """Test getting a custom quota for the persona's project

        Testing: GET /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can retrieve the custom quota for
            the project in the persona's credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_set_new_quota_for_project(self):
        """Test setting a custom quota for the persona's project

        Testing: PUT /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can create custom quotas for
            the project in the persona's credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_remove_custom_quota_for_project(self):
        """Test removing a custom quota for the persona's project

        Testing: DELETE /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can delete custom quotas for
            the project in the persona's credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_get_custom_quota_for_other_project(self):
        """Test getting a custom quota for a different project

        Testing: GET /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can retrieve the custom quota for
            a project that is different than the project in the
            persona's credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_set_new_quota_for_other_project(self):
        """Test setting a custom quota for a different project

        Testing: PUT /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can create custom quotas for a
            project that is different than the project in the
            persona's credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_remove_custom_quota_for_other_project(self):
        """Test removing a custom quota for a different project

        Testing: DELETE /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can delete custom quotas for a
            project that is different than the project in the
            persona's credentials.
        """
        raise NotImplementedError


class ProjectReaderTests(base.BarbicanV1RbacBase, BarbicanV1RbacQuota):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.QuotaClient()

    @decorators.idempotent_id('936e480a-f603-4d9e-bc77-9a69ef05ac28')
    def test_get_effective_project_quota(self):
        resp = self.client.get_default_project_quota()
        self.assertIn('quotas', resp)

    @decorators.idempotent_id('528907ad-efd8-481e-b57e-7faed7198405')
    def test_list_project_quotas(self):
        self.assertRaises(exceptions.Forbidden, self.client.list_quotas)

    @decorators.idempotent_id('948afb0d-35e8-4a23-880f-b2dc3eebf1bd')
    def test_get_custom_quota_for_project(self):
        project_id = self.client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_project_quota,
            project_id)

    @decorators.idempotent_id('c29af3ed-561e-48da-8a1b-81ba19c943bb')
    def test_set_new_quota_for_project(self):
        project_id = self.client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_project_quota,
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            }
        )

    @decorators.idempotent_id('7382fb20-01f6-4322-9ebc-5bf6038e3e1b')
    def test_remove_custom_quota_for_project(self):
        project_id = self.client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_project_quota,
            project_id)

    @decorators.idempotent_id('5d062790-6754-4d21-bd0c-08d4a74fa6f3')
    def test_get_custom_quota_for_other_project(self):
        project_id = self.other_secret_client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.get_project_quota,
            project_id)

    @decorators.idempotent_id('26bd25ab-92c2-4437-a742-f301703ce523')
    def test_set_new_quota_for_other_project(self):
        project_id = self.other_secret_client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.create_project_quota,
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            }
        )

    @decorators.idempotent_id('7a763152-c64b-42d5-9669-213681327c58')
    def test_remove_custom_quota_for_other_project(self):
        project_id = self.other_secret_client.project_id
        self.assertRaises(
            exceptions.Forbidden,
            self.client.delete_project_quota,
            project_id)


class ProjectMemberTests(ProjectReaderTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.QuotaClient()


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.QuotaClient()

    @decorators.idempotent_id('9099766d-96b3-448d-b400-3b08563d15fc')
    def test_list_project_quotas(self):
        quotas = self.client.list_quotas()
        self.assertIn("project_quotas", quotas)

    @decorators.idempotent_id('dc5125a6-bc94-4426-ba9d-03e2b03c81a8')
    def test_get_custom_quota_for_project(self):
        project_id = self.client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)

    @decorators.idempotent_id('6b169f51-9b17-4d05-aee8-849b94101246')
    def test_set_new_quota_for_project(self):
        project_id = self.client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)

    @decorators.idempotent_id('7a16b9d6-cfdc-4eb7-9e89-b824c612609e')
    def test_remove_custom_quota_for_project(self):
        project_id = self.client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)
        self.client.delete_project_quota(project_id)
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_project_quota,
            project_id)

    @decorators.idempotent_id('17936c5b-5e89-4717-9826-a22243b947cb')
    def test_get_custom_quota_for_other_project(self):
        project_id = self.other_secret_client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)

    @decorators.idempotent_id('d41c97e6-e77d-4bc4-a72d-b068294a0ef6')
    def test_set_new_quota_for_other_project(self):
        project_id = self.other_secret_client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)

    @decorators.idempotent_id('89fb47fd-bf05-4df0-bd47-282417c110b9')
    def test_remove_custom_quota_for_other_project(self):
        project_id = self.other_secret_client.tenant_id
        self.client.create_project_quota(
            project_id,
            project_quotas={
                "secrets": 1000,
                "orders": 1000,
                "containers": 1000
            })
        quota = self.client.get_project_quota(project_id)
        self.assertIn("project_quotas", quota)
        self.client.delete_project_quota(project_id)
        self.assertRaises(
            exceptions.NotFound,
            self.client.get_project_quota,
            project_id)
