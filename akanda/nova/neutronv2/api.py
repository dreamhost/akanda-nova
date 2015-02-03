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
from nova import objects
from nova.i18n import _, _LE, _LW
from nova.network import base_api
from nova.network import model as network_model
from nova.network import neutronv2
from nova.network.neutronv2 import api
from nova.openstack.common import excutils

CONF = cfg.CONF
LOG = api.LOG

update_instance_info_cache = base_api.update_instance_cache_with_nw_info


class API(api.API):

    def allocate_for_instance(self, context, instance, **kwargs):
        """Allocate network resources for the instance.

        :param context: The request context.
        :param instance: nova.objects.instance.Instance object.
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
        LOG.debug('allocate_for_instance()', instance=instance)
        if not instance.project_id:
            msg = _('empty project id for instance %s')
            raise exception.InvalidInput(
                reason=msg % instance.uuid)
        requested_networks = kwargs.get('requested_networks')
        dhcp_opts = kwargs.get('dhcp_options', None)
        ports = {}
        net_ids = []
        ordered_networks = []
        if requested_networks:
            for request in requested_networks:
                if request.port_id:
                    port = neutron.show_port(request.port_id)['port']
                    if port.get('device_id'):
                        raise exception.PortInUse(port_id=request.port_id)
                    if hypervisor_macs is not None:
                        if port['mac_address'] not in hypervisor_macs:
                            raise exception.PortNotUsable(
                                port_id=request.port_id,
                                instance=instance.uuid)
                        else:
                            # Don't try to use this MAC if we need to create a
                            # port on the fly later. Identical MACs may be
                            # configured by users into multiple ports so we
                            # discard rather than popping.
                            available_macs.discard(port['mac_address'])
                    request.network_id = port['network_id']
                    ports[request.port_id] = port
                if request.network_id:
                    net_ids.append(request.network_id)
                    ordered_networks.append(request)

        nets = self._get_available_networks(context, instance.project_id,
                                            net_ids)
        if not nets:
            LOG.warn(_LW("No network configured!"), instance=instance)
            return network_model.NetworkInfo([])

        # if this function is directly called without a requested_network param
        # or if it is indirectly called through allocate_port_for_instance()
        # with None params=(network_id=None, requested_ip=None, port_id=None,
        # pci_request_id=None):
        if (not requested_networks
                or requested_networks.is_single_unspecified):
            # bug/1267723 - if no network is requested and more
            # than one is available then raise NetworkAmbiguous Exception
            if len(nets) > 1:
                msg = _("Multiple possible networks found, use a Network "
                        "ID to be more specific.")
                raise exception.NetworkAmbiguous(msg)
            ordered_networks.append(
                objects.NetworkRequest(network_id=nets[0]['id']))

        # NOTE(melwitt): check external net attach permission after the
        #                check for ambiguity, there could be another
        #                available net which is permitted bug/1364344
        self._check_external_network_attach(context, nets)

        security_groups = kwargs.get('security_groups', [])
        security_group_ids = []

        # TODO(arosen) Should optimize more to do direct query for security
        # group if len(security_groups) == 1
        if len(security_groups):
            search_opts = {'tenant_id': instance.project_id}
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
        nets_in_requested_order = []
        for request in ordered_networks:
            # Network lookup for available network_id
            network = None
            for net in nets:
                if net['id'] == request.network_id:
                    network = net
                    break
            # if network_id did not pass validate_networks() and not available
            # here then skip it safely not continuing with a None Network
            else:
                continue

            nets_in_requested_order.append(network)
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
            request.network_id = network['id']
            zone = 'compute:%s' % instance.availability_zone
            port_req_body = {'port': {'device_id': instance.uuid,
                                      'device_owner': zone}}
            try:
                self._populate_neutron_extension_values(context,
                                                        instance,
                                                        request.pci_request_id,
                                                        port_req_body)
                # Requires admin creds to set port bindings
                port_client = (neutron if not
                               self._has_port_binding_extension(context) else
                               neutronv2.get_client(context, admin=True))
                if request.port_id:
                    port = ports[request.port_id]
                    # ---------------------------------------------------------
                    # NOTE(rods):
                    # The two line below, which are not present in the original
                    # icehouse upstream method, represent the only difference
                    # with our custom version. For further information about
                    # why we need this change, please refer to the
                    # 'Server Allocation' section of the README.md file.
                    #

                    if port['device_owner'].startswith('network:'):
                        port_req_body['port'].pop('device_owner')
                    # ---------------------------------------------------------
                    port_client.update_port(port['id'], port_req_body)
                    touched_port_ids.append(port['id'])
                    ports_in_requested_order.append(port['id'])
                else:
                    created_port = self._create_port(
                        port_client, instance, request.network_id,
                        port_req_body, request.address,
                        security_group_ids, available_macs, dhcp_opts)
                    created_port_ids.append(created_port)
                    ports_in_requested_order.append(created_port)
            except Exception:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        try:
                            port_req_body = {'port': {'device_id': ''}}
                            # Requires admin creds to set port bindings
                            if self._has_port_binding_extension(context):
                                port_req_body['port']['binding:host_id'] = None
                                port_client = neutronv2.get_client(
                                    context, admin=True)
                            else:
                                port_client = neutron
                            port_client.update_port(port_id, port_req_body)
                        except Exception:
                            msg = _LE("Failed to update port %s")
                            LOG.exception(msg, port_id)

                    self._delete_ports(neutron, instance, created_port_ids)

        nw_info = self.get_instance_nw_info(context, instance,
                                            networks=nets_in_requested_order,
                                            port_ids=ports_in_requested_order)
        # NOTE(danms): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([vif for vif in nw_info
                                          if vif['id'] in created_port_ids +
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

    def _build_network_info_model(self, context, instance, networks=None,
                                  port_ids=None):
        """Return list of ordered VIFs attached to instance.

        :param context - request context.
        :param instance - instance we are returning network info for.
        :param networks - List of networks being attached to an instance.
                          If value is None this value will be populated
                          from the existing cached value.
        :param port_ids - List of port_ids that are being attached to an
                          instance in order of attachment. If value is None
                          this value will be populated from the existing
                          cached value.
        """

        search_opts = {'tenant_id': instance['project_id'],
                       'device_id': instance['uuid'], }

        # ---------------------------------------------------------------------
        # NOTE(rods):
        # We need to relax the filter as described in the README.md file in
        # 'Network info model' section
        # The following lines are not present in the original icehouse
        # upstream method.

        if (context.project_name == 'service'
                and context.user_name == 'neutron'):
            search_opts.pop('tenant_id')
        # ---------------------------------------------------------------------

        client = neutronv2.get_client(context, admin=True)
        data = client.list_ports(**search_opts)

        current_neutron_ports = data.get('ports', [])
        networks, port_ids = self._gather_port_ids_and_networks(
            context, instance, networks, port_ids)
        nw_info = network_model.NetworkInfo()

        current_neutron_port_map = {}
        for current_neutron_port in current_neutron_ports:
            current_neutron_port_map[current_neutron_port['id']] = (
                current_neutron_port)

        for port_id in port_ids:
            current_neutron_port = current_neutron_port_map.get(port_id)
            if current_neutron_port:
                vif_active = False
                if (current_neutron_port['admin_state_up'] is False
                        or current_neutron_port['status'] == 'ACTIVE'):
                    vif_active = True

                network_IPs = self._nw_info_get_ips(client,
                                                    current_neutron_port)
                subnets = self._nw_info_get_subnets(context,
                                                    current_neutron_port,
                                                    network_IPs)

                # -------------------------------------------------------------
                # NOTE(rods):
                # Nova Havana doesn't like networks with ipv6 subnets only.
                # The following lines are not present in the original
                # icehouse upstream method.

                # TODO(rods):
                # This may not be a problem with subsequent versions of Nova,
                # we need to test and possibly remove it.
                if not any(ip['version'] == 4 for ip in network_IPs):
                    nova_lie = {
                        'cidr': '169.254.0.0/16',
                        'gateway': network_model.IP(
                            address='', type='gateway'),
                        'ips': [network_model.FixedIP(address='169.254.10.20')]
                    }
                    subnets.append(nova_lie)
                # -------------------------------------------------------------

                devname = "tap" + current_neutron_port['id']
                devname = devname[:network_model.NIC_NAME_LEN]

                network, ovs_interfaceid = (
                    self._nw_info_build_network(current_neutron_port,
                                                networks, subnets))

                nw_info.append(network_model.VIF(
                    id=current_neutron_port['id'],
                    address=current_neutron_port['mac_address'],
                    network=network,
                    type=current_neutron_port.get('binding:vif_type'),
                    details=current_neutron_port.get('binding:vif_details'),
                    ovs_interfaceid=ovs_interfaceid,
                    devname=devname,
                    active=vif_active))

        return nw_info
