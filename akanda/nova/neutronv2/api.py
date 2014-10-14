# Copyright 2014 DreamHost, LLC
#
# Author: DreamHost, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from oslo.config import cfg

from nova import exception
from nova.network import api as network_api
from nova.network import model as network_model
from nova.network import neutronv2
from nova.network.neutronv2 import api
from nova.openstack.common import excutils
from nova.openstack.common.gettextutils import _
from nova.openstack.common import jsonutils

CONF = cfg.CONF
LOG = api.LOG

update_instance_info_cache = network_api.update_instance_cache_with_nw_info


class API(api.API):

    def allocate_for_instance(self, context, instance, **kwargs):
        """Allocate network resources for the instance.

        :param requested_networks: optional value containing
            network_id, fixed_ip, and port_id
        :param security_groups: security groups to allocate for instance
        :param macs: None or a set of MAC addresses that the instance
            should use. macs is supplied by the hypervisor driver (contrast
            with requested_networks which is user supplied).
            NB: NeutronV2 currently assigns hypervisor supplied MAC addresses
            to arbitrary networks, which requires openflow switches to
            function correctly if more than one network is being used with
            the bare metal hypervisor (which is the only one known to limit
            MAC addresses).
        :param dhcp_options: None or a set of key/value pairs that should
            determine the DHCP BOOTP response, eg. for PXE booting an instance
            configured with the baremetal hypervisor. It is expected that these
            are already formatted for the neutron v2 api.
            See nova/virt/driver.py:dhcp_options_for_instance for an example.
        """
        hypervisor_macs = kwargs.get('macs', None)
        available_macs = None
        if hypervisor_macs is not None:
            # Make a copy we can mutate: records macs that have not been used
            # to create a port on a network. If we find a mac with a
            # pre-allocated port we also remove it from this set.
            available_macs = set(hypervisor_macs)
        neutron = neutronv2.get_client(context)
        LOG.debug(_('allocate_for_instance() for %s'),
                  instance['display_name'])
        if not instance['project_id']:
            msg = _('empty project id for instance %s')
            raise exception.InvalidInput(
                reason=msg % instance['display_name'])
        requested_networks = kwargs.get('requested_networks')
        dhcp_opts = kwargs.get('dhcp_options', None)
        ports = {}
        fixed_ips = {}
        net_ids = []
        if requested_networks:
            for network_id, fixed_ip, port_id in requested_networks:
                if port_id:
                    port = neutron.show_port(port_id)['port']
                    if port.get('device_id'):
                        raise exception.PortInUse(port_id=port_id)
                    if hypervisor_macs is not None:
                        if port['mac_address'] not in hypervisor_macs:
                            raise exception.PortNotUsable(
                                port_id=port_id,
                                instance=instance['display_name'])
                        else:
                            # Don't try to use this MAC if we need to create a
                            # port on the fly later. Identical MACs may be
                            # configured by users into multiple ports so we
                            # discard rather than popping.
                            available_macs.discard(port['mac_address'])
                    network_id = port['network_id']
                    ports[network_id] = port
                elif fixed_ip and network_id:
                    fixed_ips[network_id] = fixed_ip
                if network_id:
                    net_ids.append(network_id)

        nets = self._get_available_networks(context, instance['project_id'],
                                            net_ids)

        if not nets:
            LOG.warn(_("No network configured!"), instance=instance)
            return network_model.NetworkInfo([])

        security_groups = kwargs.get('security_groups', [])
        security_group_ids = []

        # TODO(arosen) Should optimize more to do direct query for security
        # group if len(security_groups) == 1
        if len(security_groups):
            search_opts = {'tenant_id': instance['project_id']}
            user_security_groups = neutron.list_security_groups(
                **search_opts).get('security_groups')

        for security_group in security_groups:
            name_match = None
            uuid_match = None
            for user_security_group in user_security_groups:
                if user_security_group['name'] == security_group:
                    if name_match:
                        raise exception.NoUniqueMatch(
                            _("Multiple security groups found matching"
                              " '%s'. Use an ID to be more specific.") %
                            security_group)

                    name_match = user_security_group['id']
                if user_security_group['id'] == security_group:
                    uuid_match = user_security_group['id']

            # If a user names the security group the same as
            # another's security groups uuid, the name takes priority.
            if not name_match and not uuid_match:
                raise exception.SecurityGroupNotFound(
                    security_group_id=security_group)
            elif name_match:
                security_group_ids.append(name_match)
            elif uuid_match:
                security_group_ids.append(uuid_match)

        touched_port_ids = []
        created_port_ids = []
        ports_in_requested_order = []
        for network in nets:
            # If security groups are requested on an instance then the
            # network must has a subnet associated with it. Some plugins
            # implement the port-security extension which requires
            # 'port_security_enabled' to be True for security groups.
            # That is why True is returned if 'port_security_enabled'
            # is not found.
            if (security_groups and not (
                    network['subnets']
                    and network.get('port_security_enabled', True))):

                raise exception.SecurityGroupCannotBeApplied()
            network_id = network['id']
            zone = 'compute:%s' % instance['availability_zone']
            # -----------------------------------------------------------------
            # NOTE(rods):
            # This change and the other below are the only differences between
            # our custom version and the original icehouse upstream method.
            # For further information about why we need these changes, please
            # refer to the 'Server Allocation' section of the README.md file.
            #
            # original code:
            # port_req_body = {'port': {'device_id': instance['uuid'],
            #                  'device_owner': zone}}

            port_req_body = {'port': {'device_id': instance['uuid']}}
            # -----------------------------------------------------------------
            try:
                port = ports.get(network_id)
                self._populate_neutron_extension_values(context, instance,
                                                        port_req_body)
                # Requires admin creds to set port bindings
                port_client = (neutron if not
                               self._has_port_binding_extension(context) else
                               neutronv2.get_client(context, admin=True))
                if port:
                    # ---------------------------------------------------------
                    # NOTE(rods):
                    # The following two lines are not present in the original
                    # icehouse upstream method.
                    if not port['device_owner'].startswith('network:'):
                        port_req_body['port']['device_owner'] = zone
                    # ---------------------------------------------------------
                    port_client.update_port(port['id'], port_req_body)
                    touched_port_ids.append(port['id'])
                    ports_in_requested_order.append(port['id'])
                else:
                    created_port = self._create_port(
                        port_client, instance, network_id,
                        port_req_body, fixed_ips.get(network_id),
                        security_group_ids, available_macs, dhcp_opts)
                    created_port_ids.append(created_port)
                    ports_in_requested_order.append(created_port)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        try:
                            port_req_body = {'port': {'device_id': None}}
                            # Requires admin creds to set port bindings
                            if self._has_port_binding_extension(context):
                                port_req_body['port']['binding:host_id'] = None
                                port_client = neutronv2.get_client(
                                    context, admin=True)
                            else:
                                port_client = neutron
                            port_client.update_port(port_id, port_req_body)
                        except Exception:
                            msg = _("Failed to update port %s")
                            LOG.exception(msg, port_id)

                    for port_id in created_port_ids:
                        try:
                            neutron.delete_port(port_id)
                        except Exception:
                            msg = _("Failed to delete port %s")
                            LOG.exception(msg, port_id)

        nw_info = self.get_instance_nw_info(context, instance, networks=nets,
                                            port_ids=ports_in_requested_order)
        # NOTE(danms): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([port for port in nw_info  # noqa
                                          if port['id'] in created_port_ids +
                                          touched_port_ids])

    def deallocate_for_instance(self, context, instance, **kwargs):
        """Deallocate all network resources related to the instance."""
        LOG.debug(_('deallocate_for_instance() for %s'),
                  instance['display_name'])

        # NOTE(rods):
        # The original icehouse upstream method works in this way:
        #   * get the list of all the ports attached to the server
        #   * create the list of ids of all the ports
        #   * get the list of ids of all the ports_to_skip
        #   * create the list of ids of the ports_to_delete, like
        #     ports = set(ports) - set(ports_to_skip)
        #   * use the ids in the lists of port_to_skip and port_to_delete to
        #     update or delete the related ports

        # As explained in the README.md file in the "Server deallocation"
        # section, to make the Nova driver able to deal with Akanda routers
        # deletion, we need to set to an empty string the device_owner
        # attribute for all those ports_to_delete whose device_owner starts
        # with the network prefix. This force us to work on list of ports
        # (not port ids as in the original method) and make some changes to
        # the logic even for a small change like test the value of an
        # attribute.

        search_opts = {'device_id': instance['uuid']}
        neutron = neutronv2.get_client(context)
        data = neutron.list_ports(**search_opts)

        requested_networks = kwargs.get('requested_networks') or {}
        ports_to_skip = [port_id for nets, fips, port_id in requested_networks]

        # ---------------------------------------------------------------------
        # NOTE(rods): Need a list of ports instead of port ids
        #
        # original code
        # ports = [port['id'] for port in data.get('ports', [])]
        # ports = set(ports) - set(ports_to_skip)

        ports = [port for port in data.get('ports', [])
                 if port['id'] not in ports_to_skip]
        # ---------------------------------------------------------------------

        # Reset device_id and device_owner for the ports that are skipped
        for port in ports_to_skip:
            port_req_body = {'port': {'device_id': '', 'device_owner': ''}}
            try:
                neutronv2.get_client(context).update_port(port,
                                                          port_req_body)
            except Exception:
                LOG.info(_('Unable to reset device ID for port %s'), port,
                         instance=instance)

        for port in ports:
            try:
                # -------------------------------------------------------------
                # NOTE(rods): check the value of the device_owner
                device_owner = port['device_owner']
                port = port['id']
                if device_owner.startswith('network:'):
                    body = dict(device_id='')
                    neutron.update_port(port, dict(port=body))
                    # ---------------------------------------------------------
                else:
                    neutron.delete_port(port)
            except neutronv2.exceptions.NeutronClientException as e:
                if e.status_code == 404:
                    LOG.warning(_("Port %s does not exist"), port)
                else:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Failed to delete neutron port %s"),
                                      port)

        # NOTE(arosen): This clears out the network_cache only if the instance
        # hasn't already been deleted. This is needed when an instance fails to
        # launch and is rescheduled onto another compute node. If the instance
        # has already been deleted this call does nothing.
        update_instance_info_cache(self, context, instance,
                                   network_model.NetworkInfo([]))

    def _build_network_info_model(self, context, instance,
                                  networks=None, port_ids=None):
        """This is a slightly different version than the super.

        Adds support to relax the filters for the service tenant.
        Workaround the fact that nova doesn't like ipv6 subnet only
        """
        search_opts = {'device_id': instance['uuid']}
        # NOTE(rods): The following "if" statement is not present in the
        #            parent method.
        if context.project_name != 'service' or context.user_name != 'neutron':
            search_opts['tenant_id'] = instance['project_id']

        client = neutronv2.get_client(context, admin=True)
        data = client.list_ports(**search_opts)
        ports = data.get('ports', [])
        if networks is None:
            # retrieve networks from info_cache to get correct nic order
            network_cache = self.conductor_api.instance_get_by_uuid(
                context, instance['uuid'])['info_cache']['network_info']
            network_cache = jsonutils.loads(network_cache)
            net_ids = [iface['network']['id'] for iface in network_cache]
            networks = self._get_available_networks(context,
                                                    instance['project_id'],
                                                    net_ids)  # akanda change

        # ensure ports are in preferred network order, and filter out
        # those not attached to one of the provided list of networks
        else:
            net_ids = [n['id'] for n in networks]
        ports = [port for port in ports if port['network_id'] in net_ids]
        api._ensure_requested_network_ordering(lambda x: x['network_id'],
                                               ports, net_ids)

        nw_info = network_model.NetworkInfo()
        for port in ports:
            network_IPs = self._nw_info_get_ips(client, port)
            subnets = self._nw_info_get_subnets(context, port, network_IPs)

            # Nova does not like only IPv6, so let's lie and add a fake
            # link-local IPv4.  Neutron provides DHCP so this is ignored.
            # NOTE(rods): This workaround is not present in the parent method
            if not any(ip['version'] == 4 for ip in network_IPs):
                nova_lie = {
                    'cidr': '169.254.0.0/16',
                    'gateway': network_model.IP(address='', type='gateway'),
                    'ips': [network_model.FixedIP(address='169.254.10.20')]
                }
                subnets.append(nova_lie)

            devname = "tap" + port['id']
            devname = devname[:network_model.NIC_NAME_LEN]

            network, ovs_interfaceid = self._nw_info_build_network(port,
                                                                   networks,
                                                                   subnets)

            nw_info.append(network_model.VIF(
                id=port['id'],
                address=port['mac_address'],
                network=network,
                type=port.get('binding:vif_type'),
                ovs_interfaceid=ovs_interfaceid,
                devname=devname))
        return nw_info
