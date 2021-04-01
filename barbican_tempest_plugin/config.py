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

from oslo_config import cfg

service_option = cfg.BoolOpt("barbican",
                             default=True,
                             help="Whether or not barbican is expected to be "
                                  "available")

barbican_tempest_group = cfg.OptGroup(
    name='barbican_tempest',
    title='Key Manager (Barbican) service options'
)

BarbicanGroupOpts = [
    cfg.BoolOpt('enable_multiple_secret_stores',
                default=False,
                help="Flag to enable mulitple secret store tests")
]

ephemeral_storage_encryption_group = cfg.OptGroup(
    name="ephemeral_storage_encryption",
    title="Ephemeral storage encryption options")

EphemeralStorageEncryptionGroup = [
    cfg.BoolOpt('enabled',
                default=False,
                help="Does the test environment support ephemeral storage "
                     "encryption?"),
    cfg.StrOpt('cipher',
               default='aes-xts-plain64',
               help="The cipher and mode used to encrypt ephemeral storage. "
                    "AES-XTS is recommended by NIST specifically for disk "
                    "storage, and the name is shorthand for AES encryption "
                    "using the XTS encryption mode. Available ciphers depend "
                    "on kernel support. At the command line, type "
                    "'cryptsetup benchmark' to determine the available "
                    "options (and see benchmark results), or go to "
                    "/proc/crypto."),
    cfg.IntOpt('key_size',
               default=256,
               help="The key size used to encrypt ephemeral storage."),
]

image_signature_verification_group = cfg.OptGroup(
    name="image_signature_verification",
    title="Image Signature Verification Options")

ImageSignatureVerificationGroup = [
    cfg.BoolOpt('enforced',
                default=True,
                help="Does the test environment enforce glance image "
                     "verification?"),
]

barbican_rbac_scope_verification_group = cfg.OptGroup(
    name="barbican_rbac_scope_verification",
    title="Barbican RBAC Verification Options")

BarbicanRBACScopeVerificationGroup = [
    cfg.BoolOpt('enforce_scope',
                default=False,
                help="Does barbican enforce scope and user "
                     "scope-aware policies?"),
]
