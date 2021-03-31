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


class ContainerClient(base.BarbicanTempestClient):

    def list_containers(self, **kwargs):
        uri = "v1/containers"
        if kwargs:
            uri += "?%s" % urllib.urlencode(kwargs)

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def get_container(self, container_id):
        uri = "v1/containers/%s" % container_id

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def create_container(self, **kwargs):
        uri = "v1/containers"

        response, body = self.post(uri, json.dumps(kwargs))
        self.expected_success(201, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_container(self, container_id):
        uri = "v1/containers/%s" % container_id

        response, _ = self.delete(uri)
        self.expected_success(204, response.status)
        return

    def add_secret_to_container(self, container_id, secret_id, **kwargs):
        uri = "v1/containers/%s/secrets" % container_id
        kwargs['secret_ref'] = "%s/v1/secrets/%s" % (
            self.auth_provider.base_url({"service": "key-manager"}),
            secret_id
        )

        response, body = self.post(
            uri,
            json.dumps(kwargs)
        )
        self.expected_success(201, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_secret_from_container(self, container_id, secret_id, **kwargs):
        uri = "v1/containers/%s/secrets" % container_id
        kwargs['secret_ref'] = "%s/v1/secrets/%s" % (
            self.auth_provider.base_url({"service": "key-manager"}),
            secret_id
        )

        response, _ = self.delete(
            uri,
            body=json.dumps(kwargs)
        )
        self.expected_success(204, response.status)
        return
