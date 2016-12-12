# Copyright 2016 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import json

from tempest import config
from tempest.lib.common import rest_client
from tempest.lib.common.utils import data_utils

CONF = config.CONF


class SecretClient(rest_client.RestClient):
    def create_secret(self, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = data_utils.rand_name("tempest-sec")

        post_body = kwargs
        body = json.dumps(post_body)
        resp, body = self.post("v1/secrets", body)
        self.expected_success(201, resp.status)
        return self._parse_resp(body)

    def delete_secret(self, secret_id):
        resp, body = self.delete("v1/secrets/%s" % secret_id)
        self.expected_success(204, resp.status)
        return body
