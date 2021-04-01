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
from tempest.lib.common.utils import data_utils

from barbican_tempest_plugin.services.key_manager.json import base


CONF = config.CONF


class SecretClient(base.BarbicanTempestClient):

    def create_secret(self, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = data_utils.rand_name("tempest-sec")

        if 'payload' in kwargs and type(kwargs['payload']) is bytes:
            kwargs['payload'] = kwargs['payload'].decode('utf-8')

        post_body = kwargs
        body = json.dumps(post_body)
        resp, body = self.post("v1/secrets", body)
        self.expected_success(201, resp.status)
        return self._parse_resp(body)

    def delete_secret(self, secret_id):
        resp, body = self.delete("v1/secrets/%s" % secret_id)
        self.expected_success(204, resp.status)
        return body

    def list_secrets(self, **kwargs):
        uri = "v1/secrets"
        if kwargs is not None:
            uri = '{base}?'.format(base=uri)

            for key in kwargs.keys():
                uri = '{base}&{name}={value}'.format(
                    base=uri,
                    name=key,
                    value=kwargs[key]
                )
        resp, body = self.get(uri)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_secret_metadata(self, secret_id):
        resp, body = self.get("v1/secrets/%s" % secret_id)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def get_secret_payload(self, secret_id):
        content_headers = {
            "Accept": "application/octet-stream"
        }
        resp, body = self.get("v1/secrets/%s/payload" % secret_id,
                              headers=content_headers)
        self.expected_success(200, resp.status)
        return self._parse_resp(body)

    def put_secret_payload(self, secret_id, payload):
        content_headers = {
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "base64"
        }
        resp, body = self.put("v1/secrets/%s" % secret_id,
                              payload,
                              headers=content_headers)
        self.expected_success(204, resp.status)
        return body
