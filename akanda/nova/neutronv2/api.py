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
        """Allocate all network resources for the instance.

        This method does not overwrite the device_owner attribute if it
        begins with network:.  This change is the only difference from the
        parent method.
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
        ports = {}
        fixed_ips = {}
        net_ids = []
        if requested_networks:
            for network_id, fixed_ip, port_id in requested_networks:
                if port_id:
                    port = neutron.show_port(port_id)['port']
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
                security_group_ids.append(name_match)
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
            zone = 'compute:%s' % CONF.default_availability_zone

            port_req_body = {'port': {'device_id': instance['uuid']}}

            try:
                port = ports.get(network_id)
                if port:
                    if not port['device_owner'].startswith('network:'):
                        port_req_body['port']['device_owner'] = zone
                    neutron.update_port(port['id'], port_req_body)
                    touched_port_ids.append(port['id'])
                else:
                    fixed_ip = fixed_ips.get(network_id)
                    if fixed_ip:
                        port_req_body['port']['fixed_ips'] = [
                            {'ip_address': fixed_ip}
                        ]
                    port_req_body['port']['network_id'] = network_id
                    port_req_body['port']['admin_state_up'] = True
                    port_req_body['port']['tenant_id'] = instance['project_id']
                    port_req_body['port']['device_owner'] = zone
                    if security_group_ids:
                        port_req_body['port']['security_groups'] = (
                            security_group_ids)
                    if available_macs is not None:
                        if not available_macs:
                            raise exception.PortNotFree(
                                instance=instance['display_name'])
                            mac_address = available_macs.pop()
                            port_req_body['port']['mac_address'] = mac_address
                    self._populate_neutron_extension_values(instance,
                                                            port_req_body)
                    created_port_ids.append(
                        neutron.create_port(port_req_body)['port']['id'])
            except Exception as e:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        port_in_server = neutron.show_port(port_id).get('port')
                        if not port_in_server:
                            raise Exception('Port have already lost')
                        port_req_body = {'port': {'device_id': None}}
                        neutron.update_port(port_id, port_req_body)

                    for port_id in created_port_ids:
                        try:
                            neutron.delete_port(port_id)
                        except Exception as ex:
                            msg = _("Fail to delete port %(portid)s with"
                                    " failure: %(exception)s")
                            LOG.debug(msg, {'portid': port_id,
                                            'exception': ex})

        self.trigger_security_group_members_refresh(context, instance)
        self.trigger_instance_add_security_group_refresh(context, instance)

        nw_info = self._get_instance_nw_info(context, instance, networks=nets)
        # NOTE(danms): Only return info about ports we created in this run.
        # In the initial allocation case, this will be everything we created,
        # and in later runs will only be what was created that time. Thus,
        # this only affects the attach case, not the original use for this
        # method.
        return network_model.NetworkInfo([
            port for port in nw_info
            if port['id'] in created_port_ids + touched_port_ids])

    def deallocate_for_instance(self, context, instance, **kwargs):
        """Deallocate all network resources related to the instance.

        This version differs from super class because it will not delete
        network owned ports.
        """
        LOG.debug(_('deallocate_for_instance() for %s'),
                  instance['display_name'])
        search_opts = {'device_id': instance['uuid']}
        data = neutronv2.get_client(context).list_ports(**search_opts)
        ports = data.get('ports', [])
        for port in ports:
            try:
                if port['device_owner'].startswith('network:'):
                    body = dict(device_id='')
                    neutronv2.get_client(context).update_port(
                        port['id'], dict(port=body))
                else:
                    neutronv2.get_client(context).delete_port(port['id'])
            except Exception as ex:
                LOG.exception(_("Failed to delete neutron port %(portid)s ")
                              % {'portid': port['id']})
        self.trigger_security_group_members_refresh(context, instance)
        self.trigger_instance_remove_security_group_refresh(context, instance)

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
