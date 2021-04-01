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
import json
from urllib import parse as urllib

from tempest import config

from barbican_tempest_plugin.services.key_manager.json import base


CONF = config.CONF


class OrderClient(base.BarbicanTempestClient):

    def list_orders(self, **kwargs):
        uri = "/v1/orders"
        if kwargs:
            uri += "?%s" % urllib.urlencode(kwargs)

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def create_order(self, **kwargs):
        uri = "/v1/orders"

        response, body = self.post(uri, json.dumps(kwargs))
        self.expected_success(202, response.status)
        return json.loads(body.decode("utf-8"))

    def get_order(self, order_id):
        uri = "v1/orders/%s" % order_id

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_order(self, order_id):
        uri = "/v1/orders/%s" % order_id

        response, _ = self.delete(uri)
        self.expected_success(204, response.status)
        return
