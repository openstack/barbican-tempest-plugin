# Copyright (c) 2016 Johns Hopkins University Applied Physics Laboratory
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from barbican_tempest_plugin.tests.api import base

from tempest import config
from tempest.lib import decorators
from tempest.lib import exceptions

CONF = config.CONF


class QuotasTest(base.BaseKeyManagerTest):
    """Quotas API tests."""

    @decorators.idempotent_id('47ebc42b-0e53-4060-b1a1-55bee2c7c43f')
    def test_get_effective_quota(self):
        if CONF.barbican_rbac_scope_verification.enforce_scope:
            # This test is using key-manager:service-admin legacy
            # role. User with only this role should get a Forbidden
            # error when trying to get effective quotas in SRBAC
            # environment.
            self.assertRaises(
                exceptions.Forbidden,
                self.quota_client.get_default_project_quota)
        else:
            body = self.quota_client.get_default_project_quota()
            quotas = body.get('quotas')
            self.assertEqual(-1, quotas.get('secrets'))
            self.assertEqual(-1, quotas.get('cas'))
            self.assertEqual(-1, quotas.get('orders'))
            self.assertEqual(-1, quotas.get('containers'))
            self.assertEqual(-1, quotas.get('consumers'))


class ProjectQuotasTest(base.BaseKeyManagerTest):

    @classmethod
    def skip_checks(cls):
        super().skip_checks()
        if CONF.barbican_rbac_scope_verification.enforce_scope:
            # These tests can't be run with the new RBAC rules because
            # the APIs they're testing require system-scoped credentials
            # instead of the project-scoped credentials used here.
            raise cls.skipException("enforce_scope is enabled for barbican, "
                                    "skipping project quota tests.")

    @decorators.idempotent_id('07dec492-7f19-4d94-a9d7-28c0643db1bc')
    def test_manage_project_quotas(self):
        # Confirm that there are no quotas
        body = self.quota_client.list_quotas()
        self.assertEqual(0, body.get('total'), body)
        self.assertEqual(0, len(body.get('project_quotas')), body)

        # Create a quota set for the test project
        self.create_project_quota(
            self.quota_client.tenant_id,
            project_quotas={
                'secrets': 30,
                'orders': 10,
                'containers': 20
            }
        )

        # Verify that the quotas can be found via generic listing.
        body = self.quota_client.list_quotas()
        self.assertEqual(1, body.get('total'), body)
        self.assertEqual(1, len(body.get('project_quotas')), body)
        project_quotas = body.get('project_quotas')[0]
        self.assertEqual(
            self.quota_client.tenant_id,
            project_quotas.get('project_id'),
            body
        )
        project_quotas = project_quotas.get('project_quotas')
        self.assertEqual(30, project_quotas.get('secrets'), body)
        self.assertEqual(10, project_quotas.get('orders'), body)
        self.assertEqual(20, project_quotas.get('containers'), body)

        # Verify that the quotas can be found via specific listing.
        body = self.quota_client.get_project_quota(
            self.quota_client.tenant_id
        )
        project_quotas = body.get('project_quotas')
        self.assertEqual(30, project_quotas.get('secrets'), body)
        self.assertEqual(10, project_quotas.get('orders'), body)
        self.assertEqual(20, project_quotas.get('containers'), body)

        # Delete the project quota and confirm that it got deleted
        self.delete_project_quota(self.quota_client.tenant_id)

        body = self.quota_client.list_quotas()
        self.assertEqual(0, body.get('total'), body)
        self.assertEqual(0, len(body.get('project_quotas')), body)
