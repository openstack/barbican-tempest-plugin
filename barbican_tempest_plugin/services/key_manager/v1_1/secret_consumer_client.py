# Copyright (c) 2022 Red Hat Inc.
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


class SecretConsumerClient(base.BarbicanTempestClient):

    _microversion = '1.1'

    def list_consumers_in_secret(self, secret_id, **kwargs):
        uri = "/v1/secrets/%s/consumers" % secret_id
        if kwargs:
            uri += "?%s" % urllib.urlencode(kwargs)

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def add_consumer_to_secret(self, secret_id, **kwargs):
        uri = "/v1/secrets/%s/consumers" % secret_id

        response, body = self.post(uri, json.dumps(kwargs))
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_consumer_from_secret(self, secret_id, **kwargs):
        uri = "/v1/secrets/%s/consumers" % secret_id

        response, body = self.delete(uri, body=json.dumps(kwargs))
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))
