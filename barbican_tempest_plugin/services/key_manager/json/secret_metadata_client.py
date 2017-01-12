# Copyright (c) 2017 Johns Hopkins University Applied Physics Laboratory
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

from tempest import config
from tempest.lib.common import rest_client

CONF = config.CONF


class SecretMetadataClient(rest_client.RestClient):

    def get_secret_metadata(self, secret_id):
        resp, body = self.get("v1/secrets/%s/metadata" % secret_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def put_secret_metadata(self, secret_id, **kwargs):
        body_dict = {'metadata': kwargs}
        uri = "v1/secrets/%s/metadata" % secret_id
        resp, body = self.put(uri, json.dumps(body_dict))
        self.expected_success(201, resp.status)
        return self._parse_resp(body)

    def get_secret_metadata_by_key(self, secret_id, key):
        uri = "v1/secrets/{uuid}/metadata/{key}".format(uuid=secret_id,
                                                        key=key)
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def create_key_value_pair(self, secret_id, key, value):
        body_dict = {
            'key': key,
            'value': value
        }
        resp, body = self.post("v1/secrets/%s/metadata" % secret_id,
                               json.dumps(body_dict))
        self.expected_success(201, resp.status)
        return self._parse_resp(body)

    def update_secret_metadata(self, secret_id, key, value):
        uri = "v1/secrets/{uuid}/metadata/{key}".format(uuid=secret_id,
                                                        key=key)
        body_dict = {
            'key': key,
            'value': value
        }
        resp, body = self.put(uri, json.dumps(body_dict))
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def delete_secret_metadata_by_key(self, secret_id, key):
        uri = "v1/secrets/{uuid}/metadata/{key}".format(uuid=secret_id,
                                                        key=key)
        resp, body = self.delete(uri)
        self.expected_success(204, resp.status)
        return self._parse_resp(body)
