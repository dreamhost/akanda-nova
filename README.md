# Akanda Nova

*Part of the [Akanda Project](https://github.com/dreamhost/akanda).*

OpenStack Nova extensions to support the Akanda project, notably to enable
efficient creation and management of Akanda software routers.


## Changes Description
To boot an Akanda router we need to tweak Nova a little to make it able to
deal with specific problems like ports ownership or port reuse.

### Server allocation
When Nova creates or reboots a server, it sets the **device_owner** attribute
of each port that will be attached(already existing or to be created) to
a value that is composed by the *compute* prefix and the name of the zone the
server has been booted in. In our case, when a server is an Akanda router, we
use special values for the **device_owner** attribute of every port. All
of these special values start with the prefix *network*. Because of this
difference, we need to prevent Nova from overriding those values.
To do that we need to change the **allocate_for_instance** method of
the Nova driver to not set the **device_owner** of a port if its value
starts with the *network* prefix or when the port needs to be created.

### Server deallocation
When a server needs to be deallocated, Nova deletes all the related ports.
In the case of an Akanda router we need to preserve the associated ports
so that we can associate them to the new Akanda router.
To do that we need to modify the **deallocate_for_instance** method of the
Nova driver to make it able to just set the **device_id** to an empty string
for all those ports whose **device_owner** attribute starts with the *network*
prefix.

### Network info model
Usually when Nova runs a server, the server is owned by the user's tenant and
all the ports the server is attached to are owned by the user in that tenant.
When Nova boot an Akanda server, things are quite different; all the routers
live in the service tenant and are owned by the neutron user. This means that
some ports are owned by the neutron user(typically ports on the public net or
the mgt net) while some others are owned by the user that is using the
associated neutron router(typically router's port on the private networks).
When Nova builds the networking info about a server it gets the list of
ports by filtering on the **device_id** and the **tenant_id**. For Akanda
routers, we need to relax the filter removing the **tenant_id** otherwise
Nova will get just some of the ports and won't be able to boot the routers.
To do that we need to override the **_build_network_info_model** method of the
Nova driver to not filter ports using the tenant_id if the requests come from the
*neutron* user in the *service* tenant.

Nova Havana doesn't like networks with ipv6 subnets only. In those cases we
workaround that modifying the **_build_network_info_model** method to add a fake
ipv4 subnet with a link-local address.
Note(rods): This may not be true for subsequent versions of Nova
