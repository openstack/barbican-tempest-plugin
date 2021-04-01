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
from urllib import parse as urllib

from tempest import config

from barbican_tempest_plugin.services.key_manager.json import base


CONF = config.CONF


class QuotaClient(base.BarbicanTempestClient):

    def list_quotas(self, **kwargs):
        uri = "v1/project-quotas"
        if kwargs:
            uri += "?%s" % urllib.urlencode(kwargs)

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def get_default_project_quota(self):
        uri = "v1/quotas"

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def get_project_quota(self, project_id):
        uri = "v1/project-quotas/%s" % project_id

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def create_project_quota(self, project_id, **kwargs):
        uri = "v1/project-quotas/%s" % project_id

        response, body = self.put(uri, json.dumps(kwargs))
        self.expected_success(204, response.status)
        return

    def delete_project_quota(self, project_id):
        uri = "v1/project-quotas/%s" % project_id

        response, _ = self.delete(uri)
        self.expected_success(204, response.status)
        return
