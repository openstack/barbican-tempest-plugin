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
from barbican_tempest_plugin.tests.rbac.v1 import base
from oslo_log import log as logging
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import decorators
from tempest.lib import exceptions


CONF = config.CONF
LOG = logging.getLogger(__name__)


class CVE20223100Test(base.BarbicanV1RbacBase):

    @decorators.idempotent_id('459159ef-9670-4c59-8528-09466185c84e')
    def test_cve_2022_3100(self):
        # create a secret that belongs to Project B
        secret_id = self.create_test_secret(
            self.other_secret_client,
            data_utils.rand_name('secret-under-test'),
            'DONT_CVE_ME_PLZ')

        # attempt to retrieve secret payload with user from Project A
        # using CVE exploit (e.g. by adding the query string
        # ?target.secret.read=read to the request)
        query = {'target.secret.read': 'read'}
        self.assertRaises(
            exceptions.Forbidden,
            self.secret_client.get_secret_payload,
            secret_id,
            **query)
