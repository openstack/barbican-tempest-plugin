#!/bin/bash
#
# This script is executed inside pre_test_hook function in devstack gate.

set -ex

export DEST=${DEST:-$BASE/new}
export DEVSTACK_DIR=${DEVSTACK_DIRE:-$DEST/devstack}
export LOCALCONF_PATH=$DEVSTACK_DIR/local.conf

# Here we can set some configurations for local.conf
# for example, to pass some config options directly to .conf files

# Set up LVM device
echo -e '[[local|localrc]]' >> $LOCALCONF_PATH
echo -e 'NOVA_BACKEND=LVM' >> $LOCALCONF_PATH
echo -e 'LVM_VOLUME_CLEAR=none' >> $LOCALCONF_PATH

# Enable image signature verification in nova.conf
echo -e '[[post-config|$NOVA_CONF]]' >> $LOCALCONF_PATH
echo -e '[glance]' >> $LOCALCONF_PATH
echo -e 'verify_glance_signatures = True' >> $LOCALCONF_PATH

# Enable ephemeral storage encryption in nova.conf
echo -e '[ephemeral_storage_encryption]' >> $LOCALCONF_PATH
echo -e 'key_size = 256' >> $LOCALCONF_PATH
echo -e 'cipher = aes-xts-plain64' >> $LOCALCONF_PATH
echo -e 'enabled = True' >> $LOCALCONF_PATH

# Allow dynamically created tempest users to create secrets
# in barbican in tempest.conf
echo -e '[[test-config|$TEMPEST_CONFIG]]' >> $LOCALCONF_PATH
echo -e '[auth]' >> $LOCALCONF_PATH
echo -e 'tempest_roles=creator' >> $LOCALCONF_PATH

# Glance v1 doesn't do signature verification on image upload
echo -e '[image-feature-enabled]' >> $LOCALCONF_PATH
echo -e 'api_v1=False' >> $LOCALCONF_PATH

# Enable ephemeral storage encryption in tempest.conf
echo -e '[ephemeral_storage_encryption]' >> $LOCALCONF_PATH
echo -e 'enabled = True' >> $LOCALCONF_PATH
