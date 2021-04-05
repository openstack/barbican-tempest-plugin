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
import json
from urllib import parse

from barbican_tempest_plugin.services.key_manager.json import base


class TransportKeyClient(base.BarbicanTempestClient):

    def list_transport_keys(self, **kwargs):
        uri = '/v1/transport_keys'
        if kwargs:
            uri += '?{}'.format(parse.urlencode(kwargs))
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return json.loads(body.decode('UTF-8'))

    def create_transport_key(self, **kwargs):
        uri = '/v1/transport_keys'
        post_body = json.dumps(kwargs)
        resp, body = self.post(uri, post_body)
        self.expected_success(201, resp.status)
        return json.loads(body.decode('UTF-8'))

    def get_transport_key(self, transport_key_id):
        uri = '/v1/transport_keys/{}'.format(transport_key_id)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return json.loads(body.decode('UTF-8'))

    def delete_transport_key(self, transport_key_id):
        uri = '/v1/transport_keys/{}'.format(transport_key_id)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
