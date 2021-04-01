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
        """Test getting a custom quota for a specific project

        Testing: GET /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can retrieve the custom quota for a
            specific project.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_set_new_quota_for_project(self):
        """Test setting a custom quota for a specific project

        Testing: PUT /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can create custom quotas for a
            specific project.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def test_remove_custom_quota_for_project(self):
        """Test removing a custom quota for a specific project

        Testing: DELETE /v1/project-quotas/{project-id}
        This test must check:
          * whether the persona can delete custom quotas for a
            specific project.
        """
        raise NotImplementedError


class ProjectMemberTests(base.BarbicanV1RbacBase, BarbicanV1RbacQuota):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_member.secret_v1.QuotaClient()

    def test_get_effective_project_quota(self):
        resp = self.do_request('get_default_project_quota')
        self.assertIn('quotas', resp)

    def test_list_project_quotas(self):
        self.do_request('list_quotas', expected_status=exceptions.Forbidden)

    def test_get_custom_quota_for_project(self):
        project_id = self.client.tenant_id
        self.do_request('get_project_quota',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id)

    def test_set_new_quota_for_project(self):
        project_id = self.client.tenant_id
        self.do_request('create_project_quota',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id)

    def test_remove_custom_quota_for_project(self):
        project_id = self.client.tenant_id
        self.do_request('delete_project_quota',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id)


class ProjectAdminTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_admin.secret_v1.QuotaClient()


class ProjectReaderTests(ProjectMemberTests):

    @classmethod
    def setup_clients(cls):
        super().setup_clients()
        cls.client = cls.os_project_reader.secret_v1.QuotaClient()
