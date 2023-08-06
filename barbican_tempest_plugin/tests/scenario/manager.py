# Copyright 2012 OpenStack Foundation
# Copyright 2013 IBM Corp.
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

from oslo_log import log

from tempest.common import waiters
from tempest import config
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

CONF = config.CONF

LOG = log.getLogger(__name__)


# we inherit from NetworkScenarioTest since some test cases need access to
# check_*_connectivity methods to validate instances are up and accessible
class ScenarioTest(manager.NetworkScenarioTest):
    """Base class for scenario tests. Uses tempest own clients. """
    # ## Test functions library
    #
    # The create_[resource] functions only return body and discard the
    # resp part which is not used in scenario tests

    def _image_create(self, name, fmt, path,
                      disk_format=None, properties=None):
        if properties is None:
            properties = {}
        name = data_utils.rand_name('%s-' % name)
        params = {
            'name': name,
            'container_format': fmt,
            'disk_format': disk_format or fmt,
            'visibility': 'private'
        }
        # Additional properties are flattened out in the v2 API.
        params.update(properties)
        body = self.image_client.create_image(**params)
        image = body['image'] if 'image' in body else body
        self.addCleanup(self.image_client.delete_image, image['id'])
        self.assertEqual("queued", image['status'])
        with open(path, 'rb') as image_file:
            self.image_client.store_image_file(image['id'], image_file)

        if CONF.image_feature_enabled.import_image:
            available_stores = []
            try:
                available_stores = self.image_client.info_stores()['stores']
            except lib_exc.NotFound:
                pass
            available_import_methods = self.image_client.info_import()[
                'import-methods']['value']
            if ('copy-image' in available_import_methods and
                    len(available_stores) > 1):
                self.image_client.image_import(image['id'],
                                               method='copy-image',
                                               all_stores=True,
                                               all_stores_must_succeed=False)
                failed_stores = waiters.wait_for_image_copied_to_stores(
                    self.image_client, image['id'])
                self.assertEqual(0, len(failed_stores),
                                 "Failed to copy the following stores: %s" %
                                 str(failed_stores))

        return image['id']
