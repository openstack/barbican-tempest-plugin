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
import urllib.parse

from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from barbican_tempest_plugin.services.key_manager.json import base


CONF = config.CONF


class SecretClient(base.BarbicanTempestClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._secret_ids = set()

    def create_secret(self, expected_status=201, **kwargs):
        if 'name' not in kwargs:
            kwargs['name'] = data_utils.rand_name("tempest-sec")

        if 'payload' in kwargs and type(kwargs['payload']) is bytes:
            kwargs['payload'] = kwargs['payload'].decode('utf-8')

        post_body = kwargs
        body = json.dumps(post_body)
        resp, body = self.post("v1/secrets", body)
        self.expected_success(expected_status, resp.status)
        resp = self._parse_resp(body)
        self._secret_ids.add(self.ref_to_uuid(resp['secret_ref']))
        return resp

    def delete_secret(self, secret_id):
        self._secret_ids.discard(secret_id)
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

    def get_secret_payload(self, secret_id, **kwargs):
        """GET /v1/secrets/{secret_id}/payload

        Retrieve the payload.If kwargs are provided they are added
        to the request as query string parameters.
        """
        content_headers = {
            "Accept": "application/octet-stream"
        }
        uri = "v1/secrets/{}/payload".format(secret_id)
        if kwargs:
            uri += '?'
            uri += urllib.parse.urlencode(kwargs)

        resp, body = self.get(uri, headers=content_headers)
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

    def get_secret_acl(self, secret_id):
        headers = {
            'Accept': 'application/json'
        }
        resp, body = self.get('v1/secrets/{}/acl'.format(secret_id),
                              headers=headers)
        self.expected_success(200, resp.status)
        return json.loads(body)

    def put_secret_acl(self, secret_id, acl):
        req_body = json.dumps(acl)
        resp, body = self.put('v1/secrets/{}/acl'.format(secret_id),
                              req_body)
        self.expected_success(200, resp.status)
        return json.loads(body)

    def patch_secret_acl(self, secret_id, acl):
        req_body = json.dumps(acl)
        resp, body = self.patch('v1/secrets/{}/acl'.format(secret_id),
                                req_body)
        self.expected_success(200, resp.status)
        return json.loads(body)

    def delete_secret_acl(self, secret_id):
        resp, body = self.delete('v1/secrets/{}/acl'.format(secret_id))
        self.expected_success(200, resp.status)
        return json.loads(body)

    def queue_for_cleanup(self, secret_id):
        self._secret_ids.add(secret_id)

    def cleanup(self):
        cleanup_ids = self._secret_ids
        self._secret_ids = set()
        for secret_id in cleanup_ids:
            try:
                self.delete_secret(secret_id)
            except exceptions.NotFound:
                pass
