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


import os

from tempest.test_discover import plugins

from barbican_tempest_plugin import config as project_config


class BarbicanTempestPlugin(plugins.TempestPlugin):
    def load_tests(self):
        base_path = os.path.split(os.path.dirname(
            os.path.abspath(__file__)))[0]
        test_dir = "barbican_tempest_plugin/tests"
        full_test_dir = os.path.join(base_path, test_dir)
        return full_test_dir, base_path

    def register_opts(self, conf):
        conf.register_opt(project_config.service_option,
                          group='service_available')

        conf.register_group(project_config.barbican_tempest_group)
        conf.register_opts(project_config.BarbicanGroupOpts,
                           project_config.barbican_tempest_group)

        # Register ephemeral storage encryption options
        conf.register_group(project_config.ephemeral_storage_encryption_group)
        conf.register_opts(project_config.EphemeralStorageEncryptionGroup,
                           project_config.ephemeral_storage_encryption_group)
        conf.register_opts(project_config.ImageSignatureVerificationGroup,
                           project_config.image_signature_verification_group)
        conf.register_group(
            project_config.barbican_rbac_scope_verification_group)
        conf.register_opts(
            project_config.BarbicanRBACScopeVerificationGroup,
            project_config.barbican_rbac_scope_verification_group
        )

    def get_opt_lists(self):
        return [('service_available', [project_config.service_option])]

    def get_service_clients(self):
        v1_params = {
            'name': 'secret_v1',
            'service_version': 'secret.v1',
            'module_path': 'barbican_tempest_plugin.services.key_manager.json',
            'client_names': [
                'ConsumerClient',
                'ContainerClient',
                'OrderClient',
                'QuotaClient',
                'SecretClient',
                'SecretMetadataClient',
                'SecretStoresClient',
                'TransportKeyClient'
            ],
        }
        return [v1_params]
