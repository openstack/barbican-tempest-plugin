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

from tempest.common import compute
from tempest.common import image as common_image
from tempest.common.utils.linux import remote_client
from tempest.common import waiters
from tempest import config
from tempest import exceptions
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager

CONF = config.CONF

LOG = log.getLogger(__name__)


# we inherit from NetworkScenarioTest since some test cases need access to
# check_*_connectivity methods to validate instances are up and accessible
class ScenarioTest(manager.NetworkScenarioTest):
    """Base class for scenario tests. Uses tempest own clients. """

    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(ScenarioTest, cls).setup_clients()
        # Clients (in alphabetical order)
        cls.flavors_client = cls.os_primary.flavors_client
        cls.compute_floating_ips_client = (
            cls.os_primary.compute_floating_ips_client)
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
        # Nova security groups client
        cls.compute_security_groups_client = (
            cls.os_primary.compute_security_groups_client)
        cls.compute_security_group_rules_client = (
            cls.os_primary.compute_security_group_rules_client)
        cls.servers_client = cls.os_primary.servers_client
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

    def _create_port(self, network_id, client=None, namestart='port-quotatest',
                     **kwargs):
        if not client:
            client = self.ports_client
        name = data_utils.rand_name(namestart)
        result = client.create_port(
            name=name,
            network_id=network_id,
            **kwargs)
        self.assertIsNotNone(result, 'Unable to allocate port')
        port = result['port']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        client.delete_port, port['id'])
        return port

    def create_keypair(self, client=None):
        if not client:
            client = self.keypairs_client
        name = data_utils.rand_name(self.__class__.__name__)
        # We don't need to create a keypair by pubkey in scenario
        body = client.create_keypair(name=name)
        self.addCleanup(client.delete_keypair, name)
        return body['keypair']

    def create_server(self, name=None, image_id=None, flavor=None,
                      validatable=False, wait_until='ACTIVE',
                      clients=None, **kwargs):
        """Wrapper utility that returns a test server.

        This wrapper utility calls the common create test server and
        returns a test server. The purpose of this wrapper is to minimize
        the impact on the code of the tests already using this
        function.
        """

        # NOTE(jlanoux): As a first step, ssh checks in the scenario
        # tests need to be run regardless of the run_validation and
        # validatable parameters and thus until the ssh validation job
        # becomes voting in CI. The test resources management and IP
        # association are taken care of in the scenario tests.
        # Therefore, the validatable parameter is set to false in all
        # those tests. In this way create_server just return a standard
        # server and the scenario tests always perform ssh checks.

        # Needed for the cross_tenant_traffic test:
        if clients is None:
            clients = self.os_primary

        if name is None:
            name = data_utils.rand_name(self.__class__.__name__ + "-server")

        vnic_type = CONF.network.port_vnic_type

        # If vnic_type is configured create port for
        # every network
        if vnic_type:
            ports = []

            create_port_body = {'binding:vnic_type': vnic_type,
                                'namestart': 'port-smoke'}
            if kwargs:
                # Convert security group names to security group ids
                # to pass to create_port
                if 'security_groups' in kwargs:
                    security_groups = \
                        clients.security_groups_client.list_security_groups(
                        ).get('security_groups')
                    sec_dict = dict([(s['name'], s['id'])
                                    for s in security_groups])

                    sec_groups_names = [s['name'] for s in kwargs.pop(
                        'security_groups')]
                    security_groups_ids = [sec_dict[s]
                                           for s in sec_groups_names]

                    if security_groups_ids:
                        create_port_body[
                            'security_groups'] = security_groups_ids
                networks = kwargs.pop('networks', [])
            else:
                networks = []

            # If there are no networks passed to us we look up
            # for the project's private networks and create a port.
            # The same behaviour as we would expect when passing
            # the call to the clients with no networks
            if not networks:
                networks = clients.networks_client.list_networks(
                    **{'router:external': False, 'fields': 'id'})['networks']

            # It's net['uuid'] if networks come from kwargs
            # and net['id'] if they come from
            # clients.networks_client.list_networks
            for net in networks:
                net_id = net.get('uuid', net.get('id'))
                if 'port' not in net:
                    port = self._create_port(network_id=net_id,
                                             client=clients.ports_client,
                                             **create_port_body)
                    ports.append({'port': port['id']})
                else:
                    ports.append({'port': net['port']})
            if ports:
                kwargs['networks'] = ports
            self.ports = ports

        tenant_network = self.get_tenant_network()

        body, servers = compute.create_test_server(
            clients,
            tenant_network=tenant_network,
            wait_until=wait_until,
            name=name, flavor=flavor,
            image_id=image_id, **kwargs)

        self.addCleanup(waiters.wait_for_server_termination,
                        clients.servers_client, body['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        clients.servers_client.delete_server, body['id'])
        server = clients.servers_client.show_server(body['id'])['server']
        return server

    def create_volume(self, size=None, name=None, snapshot_id=None,
                      imageRef=None, volume_type=None):
        if size is None:
            size = CONF.volume.volume_size
        if imageRef:
            image = self.compute_images_client.show_image(imageRef)['image']
            min_disk = image.get('minDisk')
            size = max(size, min_disk)
        if name is None:
            name = data_utils.rand_name(self.__class__.__name__ + "-volume")
        kwargs = {'display_name': name,
                  'snapshot_id': snapshot_id,
                  'imageRef': imageRef,
                  'volume_type': volume_type,
                  'size': size}
        if CONF.compute.compute_volume_common_az:
            kwargs.setdefault('availability_zone',
                              CONF.compute.compute_volume_common_az)
        volume = self.volumes_client.create_volume(**kwargs)['volume']

        self.addCleanup(self.volumes_client.wait_for_resource_deletion,
                        volume['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.volumes_client.delete_volume, volume['id'])

        # NOTE(e0ne): Cinder API v2 uses name instead of display_name
        if 'display_name' in volume:
            self.assertEqual(name, volume['display_name'])
        else:
            self.assertEqual(name, volume['name'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')
        # The volume retrieved on creation has a non-up-to-date status.
        # Retrieval after it becomes active ensures correct details.
        volume = self.volumes_client.show_volume(volume['id'])['volume']
        return volume

    def create_volume_type(self, client=None, name=None, backend_name=None):
        if not client:
            client = self.admin_volume_types_client
        if not name:
            class_name = self.__class__.__name__
            name = data_utils.rand_name(class_name + '-volume-type')
        randomized_name = data_utils.rand_name('scenario-type-' + name)

        LOG.debug("Creating a volume type: %s on backend %s",
                  randomized_name, backend_name)
        extra_specs = {}
        if backend_name:
            extra_specs = {"volume_backend_name": backend_name}

        body = client.create_volume_type(name=randomized_name,
                                         extra_specs=extra_specs)
        volume_type = body['volume_type']
        self.assertIn('id', volume_type)
        self.addCleanup(client.delete_volume_type, volume_type['id'])
        return volume_type

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
            except exceptions.NotFound:
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

    def rebuild_server(self, server_id, image=None,
                       preserve_ephemeral=False, wait=True,
                       rebuild_kwargs=None):
        if image is None:
            image = CONF.compute.image_ref

        rebuild_kwargs = rebuild_kwargs or {}

        LOG.debug("Rebuilding server (id: %s, image: %s, preserve eph: %s)",
                  server_id, image, preserve_ephemeral)
        self.servers_client.rebuild_server(
            server_id=server_id, image_ref=image,
            preserve_ephemeral=preserve_ephemeral,
            **rebuild_kwargs)
        if wait:
            waiters.wait_for_server_status(self.servers_client,
                                           server_id, 'ACTIVE')

    def create_floating_ip(self, thing, pool_name=None):
        """Create a floating IP and associates to a server on Nova"""

        if not pool_name:
            pool_name = CONF.network.floating_network_name
        floating_ip = (self.compute_floating_ips_client.
                       create_floating_ip(pool=pool_name)['floating_ip'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.compute_floating_ips_client.delete_floating_ip,
                        floating_ip['id'])
        self.compute_floating_ips_client.associate_floating_ip_to_server(
            floating_ip['ip'], thing['id'])
        return floating_ip

    def nova_volume_attach(self, server, volume_to_attach):
        volume = self.servers_client.attach_volume(
            server['id'], volumeId=volume_to_attach['id'], device='/dev/%s'
            % CONF.compute.volume_device_name)['volumeAttachment']
        self.assertEqual(volume_to_attach['id'], volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'in-use')

        self.addCleanup(self.nova_volume_detach, server, volume)
        # Return the updated volume after the attachment
        return self.volumes_client.show_volume(volume['id'])['volume']

    def nova_volume_detach(self, server, volume):
        self.servers_client.detach_volume(server['id'], volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')

        volume = self.volumes_client.show_volume(volume['id'])['volume']
        self.assertEqual('available', volume['status'])

    def create_timestamp(self, ip_address, dev_name=None, mount_path='/mnt',
                         private_key=None):
        ssh_client = self.get_remote_client(ip_address,
                                            private_key=private_key)
        if dev_name is not None:
            ssh_client.make_fs(dev_name)
            ssh_client.exec_command('sudo mount /dev/%s %s' % (dev_name,
                                                               mount_path))
        cmd_timestamp = 'sudo sh -c "date > %s/timestamp; sync"' % mount_path
        ssh_client.exec_command(cmd_timestamp)
        timestamp = ssh_client.exec_command('sudo cat %s/timestamp'
                                            % mount_path)
        if dev_name is not None:
            ssh_client.exec_command('sudo umount %s' % mount_path)
        return timestamp

    def get_timestamp(self, ip_address, dev_name=None, mount_path='/mnt',
                      private_key=None):
        ssh_client = self.get_remote_client(ip_address,
                                            private_key=private_key)
        if dev_name is not None:
            ssh_client.mount(dev_name, mount_path)
        timestamp = ssh_client.exec_command('sudo cat %s/timestamp'
                                            % mount_path)
        if dev_name is not None:
            ssh_client.exec_command('sudo umount %s' % mount_path)
        return timestamp

    def get_server_ip(self, server):
        """Get the server fixed or floating IP.

        Based on the configuration we're in, return a correct ip
        address for validating that a guest is up.
        """
        if CONF.validation.connect_method == 'floating':
            # The tests calling this method don't have a floating IP
            # and can't make use of the validation resources. So the
            # method is creating the floating IP there.
            return self.create_floating_ip(server)['ip']
        elif CONF.validation.connect_method == 'fixed':
            # Determine the network name to look for based on config or creds
            # provider network resources.
            if CONF.validation.network_for_ssh:
                addresses = server['addresses'][
                    CONF.validation.network_for_ssh]
            else:
                creds_provider = self._get_credentials_provider()
                net_creds = creds_provider.get_primary_creds()
                network = getattr(net_creds, 'network', None)
                addresses = (server['addresses'][network['name']]
                             if network else [])
            for address in addresses:
                ip_version_for_ssh = CONF.validation.ip_version_for_ssh
                if (address['version'] == ip_version_for_ssh and
                        address['OS-EXT-IPS:type'] == 'fixed'):
                    return address['addr']
            raise exceptions.ServerUnreachable(server_id=server['id'])
        else:
            raise lib_exc.InvalidConfiguration()

    def get_remote_client(self, ip_address, username=None, private_key=None):
        """Get a SSH client to a remote server

        @param ip_address the server floating or fixed IP address to use
                          for ssh validation
        @param username name of the Linux account on the remote server
        @param private_key the SSH private key to use
        @return a RemoteClient object
        """

        if username is None:
            username = CONF.validation.image_ssh_user
        # Set this with 'keypair' or others to log in with keypair or
        # username/password.
        if CONF.validation.auth_method == 'keypair':
            password = None
            if private_key is None:
                private_key = self.keypair['private_key']
        else:
            password = CONF.validation.image_ssh_password
            private_key = None
        linux_client = remote_client.RemoteClient(ip_address, username,
                                                  pkey=private_key,
                                                  password=password)
        try:
            linux_client.validate_authentication()
        except Exception as e:
            message = ('Initializing SSH connection to %(ip)s failed. '
                       'Error: %(error)s' % {'ip': ip_address,
                                             'error': e})
            caller = test_utils.find_test_caller()
            if caller:
                message = '(%s) %s' % (caller, message)
            LOG.exception(message)
            self._log_console_output()
            raise

        return linux_client

    def _default_security_group(self, client=None, tenant_id=None):
        """Get default secgroup for given tenant_id.

        :returns: default secgroup for given tenant
        """
        if client is None:
            client = self.security_groups_client
        if not tenant_id:
            tenant_id = client.tenant_id
        sgs = [
            sg for sg in list(client.list_security_groups().values())[0]
            if sg['tenant_id'] == tenant_id and sg['name'] == 'default'
        ]
        msg = "No default security group for tenant %s." % (tenant_id)
        self.assertGreater(len(sgs), 0, msg)
        return sgs[0]

    def _create_security_group(self):
        # Create security group
        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        secgroup = self.compute_security_groups_client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.compute_security_groups_client.delete_security_group,
            secgroup['id'])

        # Add rules to the security group
        self._create_loginable_secgroup_rule(secgroup['id'])

        return secgroup

    def _create_loginable_secgroup_rule(self, secgroup_id=None):
        _client = self.compute_security_groups_client
        _client_rules = self.compute_security_group_rules_client
        if secgroup_id is None:
            sgs = _client.list_security_groups()['security_groups']
            for sg in sgs:
                if sg['name'] == 'default':
                    secgroup_id = sg['id']

        # These rules are intended to permit inbound ssh and icmp
        # traffic from all sources, so no group_id is provided.
        # Setting a group_id would only permit traffic from ports
        # belonging to the same security group.
        rulesets = [
            {
                # ssh
                'ip_protocol': 'tcp',
                'from_port': 22,
                'to_port': 22,
                'cidr': '0.0.0.0/0',
            },
            {
                # ping
                'ip_protocol': 'icmp',
                'from_port': -1,
                'to_port': -1,
                'cidr': '0.0.0.0/0',
            }
        ]
        rules = list()
        for ruleset in rulesets:
            sg_rule = _client_rules.create_security_group_rule(
                parent_group_id=secgroup_id, **ruleset)['security_group_rule']
            rules.append(sg_rule)
        return rules

    def _create_security_group_rule(self, secgroup=None,
                                    sec_group_rules_client=None,
                                    tenant_id=None,
                                    security_groups_client=None, **kwargs):
        """Create a rule from a dictionary of rule parameters.

        Create a rule in a secgroup. if secgroup not defined will search for
        default secgroup in tenant_id.

        :param secgroup: the security group.
        :param tenant_id: if secgroup not passed -- the tenant in which to
            search for default secgroup
        :param kwargs: a dictionary containing rule parameters:
            for example, to allow incoming ssh:
            rule = {
                    direction: 'ingress'
                    protocol:'tcp',
                    port_range_min: 22,
                    port_range_max: 22
                    }
        """
        if sec_group_rules_client is None:
            sec_group_rules_client = self.security_group_rules_client
        if security_groups_client is None:
            security_groups_client = self.security_groups_client
        if not tenant_id:
            tenant_id = security_groups_client.tenant_id
        if secgroup is None:
            secgroup = self._default_security_group(
                client=security_groups_client, tenant_id=tenant_id)

        ruleset = dict(security_group_id=secgroup['id'],
                       tenant_id=secgroup['tenant_id'])
        ruleset.update(kwargs)

        sg_rule = sec_group_rules_client.create_security_group_rule(**ruleset)
        sg_rule = sg_rule['security_group_rule']

        self.assertEqual(secgroup['tenant_id'], sg_rule['tenant_id'])
        self.assertEqual(secgroup['id'], sg_rule['security_group_id'])

        return sg_rule
