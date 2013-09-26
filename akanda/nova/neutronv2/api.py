from oslo.config import cfg

from nova import exception
from nova.network import api as network_api
from nova.network import model as network_model
from nova.network import neutronv2
from nova.network.neutronv2 import api
from nova.openstack.common import excutils
from nova.openstack.common import log as logging

CONF = cfg.CONF
LOG = api.LOG


class API(api.API):

    @network_api.refresh_cache
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
            are already formatted for the quantum v2 api.
            See nova/virt/driver.py:dhcp_options_for_instance for an example.

        NOTE: This method does not overwrite the device_owner attribute if it
              begins with "network:".  This change is the only difference from
              the parent method.
        """
        hypervisor_macs = kwargs.get('macs', None)
        available_macs = None
        dhcp_opts = None
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
        # Note: (dkehn) this option check should be removed as soon as support
        # in neutron released, see https://bugs.launchpad.net/nova/+bug/1214162
        if CONF.dhcp_options_enabled:
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
                                instance=instance['display_name']
                            )
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
            return []

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
                        msg = (_("Multiple security groups found matching"
                                 " '%s'. Use an ID to be more specific."),
                               security_group)
                        raise exception.NoUniqueMatch(msg)
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
            port_req_body = {'port': {'device_id': instance['uuid'],
                                      'device_owner': zone}}
            try:
                port = ports.get(network_id)
                self._populate_neutron_extension_values(instance,
                                                        port_req_body)
                # Requires admin creds to set port bindings
                port_client = (neutron if not
                               self._has_port_binding_extension() else
                               neutronv2.get_client(context, admin=True))
                if port:
                    # NOTE(rods): Add the following two lines is the only
                    #             change from the parent method
                    if not port['device_owner'].startswith('network:'):
                        port_req_body['port']['device_owner'] = zone
                    port_client.update_port(port['id'], port_req_body)
                    touched_port_ids.append(port['id'])
                else:
                    created_port_ids.append(
                        self._create_port(
                            port_client, instance, network_id,
                            port_req_body, fixed_ips.get(network_id),
                            security_group_ids, available_macs, dhcp_opts)
                    )
            except Exception:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        try:
                            port_req_body = {'port': {'device_id': None}}
                            # Requires admin creds to set port bindings
                            if self._has_port_binding_extension():
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

        nw_info = self._get_instance_nw_info(context, instance, networks=nets)
        # NOTE(danms): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([port for port in nw_info
                                          if port['id'] in created_port_ids +
                                          touched_port_ids])

    def deallocate_for_instance(self, context, instance, **kwargs):
        """Deallocate all network resources related to the instance.

        This version differs from super class because it will not delete
        network owned ports.
        """
        LOG.debug(_('deallocate_for_instance() for %s'),
                  instance['display_name'])
        search_opts = {'device_id': instance['uuid']}
        data = neutronv2.get_client(context).list_ports(**search_opts)
        ports = [port['id'] for port in data.get('ports', [])]

        requested_networks = kwargs.get('requested_networks') or {}
        ports_to_skip = [port_id for nets, fips, port_id in requested_networks]
        ports = set(ports) - set(ports_to_skip)

        for port in ports:
            try:
                # NOTE(rods): The following 'if' statement is the only
                #             difference with the parent method
                _port = data['ports']['port']
                if _port['device_owner'].startswith('network:'):
                    body = dict(device_id='')
                    neutronv2.get_client(context).update_port(
                        port['id'], dict(port=body))
                else:
                    neutronv2.get_client(context).delete_port(port)
            except Exception:
                LOG.exception(_("Failed to delete neutron port %(portid)s")
                              % {'portid': port})

    def _build_network_info_model(self, context, instance, networks=None):
        """This is a slightly different version than the super.

        Adds support to relax the filters for the service tenant. Additionally,
        attempts are made to preserve network ordering.
        """
        search_opts = {'device_id': instance['uuid']}

        if context.project_name != 'service' or context.user_name != 'neutron':
            search_opts['tenant_id'] = instance['project_id']

        client = neutronv2.get_client(context, admin=True)
        data = client.list_ports(**search_opts)
        ports = data.get('ports', [])
        if networks is None:
            networks = self._get_available_networks(context,
                                                    instance['project_id'])
        else:
            # ensure ports are in preferred network order
            api._ensure_requested_network_ordering(
                lambda x: x['network_id'],
                ports,
                [n['id'] for n in networks])

        nw_info = network_model.NetworkInfo()
        for port in ports:
            network_name = None
            for net in networks:
                if port['network_id'] == net['id']:
                    network_name = net['name']
                    break

            if network_name is None:
                raise exception.NotFound(_('Network %(net)s for '
                                           'port %(port_id)s not found!') %
                                         {'net': port['network_id'],
                                          'port': port['id']})

            network_IPs = []
            for fixed_ip in port['fixed_ips']:
                fixed = network_model.FixedIP(address=fixed_ip['ip_address'])
                floats = self._get_floating_ips_by_fixed_and_port(
                    client, fixed_ip['ip_address'], port['id'])
                for ip in floats:
                    fip = network_model.IP(address=ip['floating_ip_address'],
                                           type='floating')
                    fixed.add_floating_ip(fip)
                network_IPs.append(fixed)

            subnets = self._get_subnets_from_port(context, port)
            for subnet in subnets:
                subnet['ips'] = [fixed_ip for fixed_ip in network_IPs
                                 if fixed_ip.is_in_subnet(subnet)]

            #Nova does not like only IPv6, so let's lie and add a fake
            # link-local IPv4.  Neutron provides DHCP so this is ignored.
            if not any(ip['version'] == 4 for ip in network_IPs):
                nova_lie = {
                    'cidr': '169.254.0.0/16',
                    'gateway': network_model.IP(address='', type='gateway'),
                    'ips': [network_model.FixedIP(address='169.254.10.20')]
                }
                subnets.append(nova_lie)

            bridge = None
            ovs_interfaceid = None
            # Network model metadata
            should_create_bridge = None
            vif_type = port.get('binding:vif_type')
            # TODO(berrange) Neutron should pass the bridge name
            # in another binding metadata field
            if vif_type == network_model.VIF_TYPE_OVS:
                bridge = CONF.neutron_ovs_bridge
                ovs_interfaceid = port['id']
            elif vif_type == network_model.VIF_TYPE_BRIDGE:
                bridge = "brq" + port['network_id']
                should_create_bridge = True

            if bridge is not None:
                bridge = bridge[:network_model.NIC_NAME_LEN]

            devname = "tap" + port['id']
            devname = devname[:network_model.NIC_NAME_LEN]

            network = network_model.Network(
                id=port['network_id'],
                bridge=bridge,
                injected=CONF.flat_injected,
                label=network_name,
                tenant_id=net['tenant_id']
            )
            network['subnets'] = subnets
            if should_create_bridge is not None:
                network['should_create_bridge'] = should_create_bridge
            nw_info.append(network_model.VIF(
                id=port['id'],
                address=port['mac_address'],
                network=network,
                type=port.get('binding:vif_type'),
                ovs_interfaceid=ovs_interfaceid,
                devname=devname))
        return nw_info
