===============================
Tempest Integration of Barbican
===============================

This project defines a tempest plugin containing tests used to verify the
functionality of a barbican installation. The plugin will automatically load
these tests into tempest.

Dependencies
------------
The barbican_tempest_plugin tests the barbican quota API, which requires the
existence of the 'key-manager:service-admin' role in barbican. The quota API
tests will fail if this role is not defined.

Developers
----------
For more information on barbican, refer to:
http://docs.openstack.org/developer/barbican/

For more information on tempest plugins, refer to:
http://docs.openstack.org/developer/tempest/plugin.html#using-plugins

Bugs
----
Please report bugs to: http://bugs.launchpad.net/barbican
