from nova import exception
from nova import flags
from nova.network import model as network_model
from nova.network import quantumv2
from nova.network.quantumv2 import api
from nova.openstack.common import excutils
from nova.openstack.common import log as logging

FLAGS = flags.FLAGS
LOG = api.LOG


class API(api.API):
    def _get_available_networks(self, context, project_id, net_ids=None):
        """Return a list of available networks for the tenant.

        This version is more permissive and allows the quantum service user
        to see more networks by relying on Quantum to properly
        filter the networks.
        """
        if (context.project_name == 'service' and
            context.user_name == 'quantum'):
            f = self._akanda_available_networks
        else:
            f = super(API, self)._get_available_networks

        unordered = f(context, project_id, net_ids)
        if net_ids:
            # now sort the networks into the requested for consistency
            return _sort_helper(unordered, 'id', net_ids)
        else:
            return unordered

    def _akanda_available_networks(self, context, project_id, net_ids=None):
        quantum = quantumv2.get_client(context)

        search_opts = {}

        if net_ids:
            search_opts['id'] = net_ids
        return quantum.list_networks(**search_opts).get('networks', [])

    def allocate_for_instance(self, context, instance, **kwargs):
        """Allocate all network resources for the instance.

        This method does not overwrite the device_owner attribute if it
        begins with network:.  This change is the only difference from the
        parent method.
        """
        quantum = quantumv2.get_client(context)
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
                    port = quantum.show_port(port_id).get('port')
                    network_id = port['network_id']
                    ports[network_id] = port
                elif fixed_ip:
                    fixed_ips[network_id] = fixed_ip
                net_ids.append(network_id)

        nets = self._get_available_networks(context, instance['project_id'],
                                            net_ids)

        touched_port_ids = []
        created_port_ids = []
        for network in nets:
            network_id = network['id']
            zone = 'compute:%s' % FLAGS.node_availability_zone
            port_req_body = {'device_id': instance['uuid']}
            try:
                port = ports.get(network_id)
                if port:
                    if not port['device_owner'].startswith('network:'):
                        port_req_body['device_owner'] = zone
                    quantum.update_port(port['id'], dict(port=port_req_body))
                    touched_port_ids.append(port['id'])
                else:
                    if fixed_ips.get(network_id):
                        port_req_body['fixed_ip'] = fixed_ip
                    port_req_body['network_id'] = network_id
                    port_req_body['admin_state_up'] = True
                    port_req_body['tenant_id'] = instance['project_id']
                    port_req_body['device_owner'] = zone
                    created_port_ids.append(
                        quantum.create_port(
                            dict(port=port_req_body))['port']['id'])
            except Exception:
                with excutils.save_and_reraise_exception():
                    for port_id in touched_port_ids:
                        port_in_server = quantum.show_port(port_id).get('port')
                        if not port_in_server:
                            raise Exception('Port have already lost')
                        port_req_body = {'port': {'device_id': None}}
                        quantum.update_port(port_id, port_req_body)

                    for port_id in created_port_ids:
                        try:
                            quantum.delete_port(port_id)
                        except Exception as ex:
                            msg = _("Fail to delete port %(portid)s with"
                                    " failure: %(exception)s")
                            LOG.debug(msg, {'portid': port_id,
                                            'exception': ex})

        self.trigger_security_group_members_refresh(context, instance)

        return self.get_instance_nw_info(context, instance, networks=nets)

    def deallocate_for_instance(self, context, instance, **kwargs):
        """Deallocate all network resources related to the instance.

        This version differs from super class because it will not delete
        network owned ports.
        """
        LOG.debug(_('deallocate_for_instance() for %s'),
                  instance['display_name'])
        search_opts = {'device_id': instance['uuid']}
        data = quantumv2.get_client(context).list_ports(**search_opts)
        ports = data.get('ports', [])
        for port in ports:
            try:
                if port['device_owner'].startswith('network:'):
                    body = dict(device_id='')
                    quantumv2.get_client(context).update_port(
                        port['id'], dict(port=body))
                else:
                    quantumv2.get_client(context).delete_port(port['id'])
            except Exception as ex:
                LOG.exception(_("Failed to delete quantum port %(portid)s ")
                              % {'portid': port['id']})
        self.trigger_security_group_members_refresh(context, instance)

    def _build_network_info_model(self, context, instance, networks=None):
        """This is a slightly different version than the super.

        Adds support to relax the filters for the service tenant. Additionally,
        attempts are made to preserve network ordering.
        """
        search_opts = {'device_id': instance['uuid']}

        if context.project_name != 'service' or context.user_name != 'quantum':
            search_opts['tenant_id'] = instance['project_id']

        data = quantumv2.get_client(context).list_ports(**search_opts)
        ports = data.get('ports', [])
        if not networks:
            networks = self._get_available_networks(context,
                                                    instance['project_id'])
        else:
            ports = _sort_helper(
                ports,
                'network_id',
                [n['id'] for n in networks])

        nw_info = network_model.NetworkInfo()
        for port in ports:
            network_name = None
            for net in networks:
                if port['network_id'] == net['id']:
                    network_name = net['name']
                    break

            network_IPs = [network_model.FixedIP(address=ip_address)
                           for ip_address in [ip['ip_address']
                                              for ip in port['fixed_ips']]]

            # TODO(gongysh) get floating_ips for each fixed_ip

            subnets = self._get_subnets_from_port(context, port)
            for subnet in subnets:
                subnet['ips'] = [fixed_ip for fixed_ip in network_IPs
                                 if fixed_ip.is_in_subnet(subnet)]

            #Nova does not like only IPv6, so let's lie and add a fake
            # link-local IPv4.  Quantum provides DHCP so this is ignored.
            if not any(ip['version'] == 4 for ip in network_IPs):
                nova_lie = {
                    'cidr': '169.254.0.0/16',
                    'gateway': network_model.IP(address='', type='gateway'),
                    'ips': [network_model.FixedIP(address='169.254.10.20')]
                }
                subnets.append(nova_lie)

            network = network_model.Network(
                id=port['network_id'],
                bridge='',  # Quantum ignores this field
                injected=FLAGS.flat_injected,
                label=network_name,
                tenant_id=net['tenant_id']
            )
            network['subnets'] = subnets
            nw_info.append(network_model.VIF(
                id=port['id'],
                address=port['mac_address'],
                network=network))
        return nw_info


def _sort_helper(list_of_dicts, key, networks):
    temp = [(networks.index(d[key]), d) for d in list_of_dicts]
    return [x[1] for x in sorted(temp)]
