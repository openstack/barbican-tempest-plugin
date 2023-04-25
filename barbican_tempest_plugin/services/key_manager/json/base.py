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
from tempest import config
from tempest.lib.common import rest_client

CONF = config.CONF

_DEFAULT_SERVICE_TYPE = 'key-manager'
_DEFAULT_REGION = CONF.key_manager.region
_MICROVERSION_HEADER = 'OpenStack-API-Version'


class BarbicanTempestClient(rest_client.RestClient):

    _microversion = None

    def __init__(self, *args, **kwargs):
        kwargs['service'] = _DEFAULT_SERVICE_TYPE
        kwargs['region'] = _DEFAULT_REGION
        super().__init__(*args, **kwargs)

    def get_headers(self, accept_type=None, send_type=None):
        headers = super().get_headers(accept_type, send_type)
        if self._microversion:
            headers[_MICROVERSION_HEADER] = \
                f'{_DEFAULT_SERVICE_TYPE} {self._microversion}'
        return headers

    @classmethod
    def ref_to_uuid(cls, href):
        return href.split('/')[-1]
