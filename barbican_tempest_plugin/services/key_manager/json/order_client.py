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
from tempest.lib import exceptions

from barbican_tempest_plugin.services.key_manager.json import base


CONF = config.CONF


class OrderClient(base.BarbicanTempestClient):

    def __init__(self, *args, secret_client=None, container_client=None,
                 **kwargs):
        """Create a new order client

        secret_client and container_client are optional and will be used
        to queue the respective objects for cleanup when given.
        """
        super().__init__(*args, **kwargs)
        self._order_ids = set()
        self._secret_client = secret_client
        self._container_client = container_client

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
        resp = json.loads(body.decode("utf-8"))
        self._order_ids.add(self.ref_to_uuid(resp['order_ref']))
        return resp

    def get_order(self, order_id):
        uri = "v1/orders/%s" % order_id

        response, body = self.get(uri)
        self.expected_success(200, response.status)
        return json.loads(body.decode("utf-8"))

    def delete_order(self, order_id):
        self._order_ids.discard(order_id)
        uri = "/v1/orders/%s" % order_id

        self._queue_cleanup(order_id)

        response, _ = self.delete(uri)
        self.expected_success(204, response.status)
        return

    def cleanup(self):
        """Attempt to delete all orders created by this client

        If this client was instantiated with secret and/or container
        clients, then we try to queue for cleanup any objects generated
        by the orders.
        """
        cleanup_ids = self._order_ids
        self._order_ids = set()
        for order_id in cleanup_ids:
            self._queue_cleanup(order_id)
            try:
                self.delete_order(order_id)
            except exceptions.NotFound:
                continue

    def _queue_cleanup(self, order_id):
        try:
            order = self.get_order(order_id)
        except exceptions.NotFound:
            pass
        except exceptions.Forbidden:
            pass
        else:
            if (self._secret_client is not None) and \
                    (order.get('secret_ref') is not None):
                self._secret_client.queue_for_cleanup(
                    self.ref_to_uuid(order['secret_ref'])
                )
            if (self._container_client is not None) and \
                    (order.get('container_ref') is not None):
                self._container_client.queue_for_cleanup(
                    self.ref_to_uuid(order['container_ref'])
                )
