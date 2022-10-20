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

from tempest.common import image as common_image
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

    @classmethod
    def setup_clients(cls):
        super(ScenarioTest, cls).setup_clients()
        # Clients (in alphabetical order)
        cls.flavors_client = cls.os_primary.flavors_client
        if CONF.service_available.glance:
            # Check if glance v1 is available to determine which client to use.
            if CONF.image_feature_enabled.api_v1:
                cls.image_client = cls.os_primary.image_client
            elif CONF.image_feature_enabled.api_v2:
                cls.image_client = cls.os_primary.image_client_v2
            else:
                raise lib_exc.InvalidConfiguration(
                    'Either api_v1 or api_v2 must be True in '
                    '[image-feature-enabled].')
        # Compute image client
        cls.compute_images_client = cls.os_primary.compute_images_client
        cls.keypairs_client = cls.os_primary.keypairs_client
        # Neutron network client
        cls.networks_client = cls.os_primary.networks_client
        cls.ports_client = cls.os_primary.ports_client
        cls.routers_client = cls.os_primary.routers_client
        cls.subnets_client = cls.os_primary.subnets_client
        cls.floating_ips_client = cls.os_primary.floating_ips_client
        cls.security_groups_client = cls.os_primary.security_groups_client
        cls.security_group_rules_client = (
            cls.os_primary.security_group_rules_client)

        cls.volumes_client = cls.os_primary.volumes_client_latest
        cls.snapshots_client = cls.os_primary.snapshots_client_latest

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
        }
        if CONF.image_feature_enabled.api_v1:
            params['is_public'] = 'False'
            params['properties'] = properties
            params = {'headers': common_image.image_meta_to_headers(**params)}
        else:
            params['visibility'] = 'private'
            # Additional properties are flattened out in the v2 API.
            params.update(properties)
        body = self.image_client.create_image(**params)
        image = body['image'] if 'image' in body else body
        self.addCleanup(self.image_client.delete_image, image['id'])
        self.assertEqual("queued", image['status'])
        with open(path, 'rb') as image_file:
            if CONF.image_feature_enabled.api_v1:
                self.image_client.update_image(image['id'], data=image_file)
            else:
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
