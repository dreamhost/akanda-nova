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


# Copyright 2012 OpenStack LLC.
# All Rights Reserved
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
#
# vim: tabstop=4 shiftwidth=4 softtabstop=4

from oslo.config import cfg

from nova.openstack.common import excutils
from nova.openstack.common import log as logging
from neutronclient import client
from neutronclient.v2_0 import client as clientv20

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


def _get_auth_token():
    try:
        httpclient = client.HTTPClient(
            username=CONF.neutron_admin_username,
            tenant_name=CONF.neutron_admin_tenant_name,
            password=CONF.neutron_admin_password,
            auth_url=CONF.neutron_admin_auth_url,
            timeout=CONF.neutron_url_timeout,
            auth_strategy=CONF.neutron_auth_strategy)
        httpclient.authenticate()
    except Exception:
        with excutils.save_and_reraise_exception():
            LOG.exception(_("_get_auth_token() failed"))
    return httpclient.auth_token


def get_client(context):
    token = context.auth_token
    if not token:
        if CONF.neutron_auth_strategy:
            token = _get_auth_token()
    if token:
        my_client = clientv20.Client(
            endpoint_url=CONF.neutron_url,
            token=token, timeout=CONF.neutron_url_timeout)
    else:
        my_client = clientv20.Client(
            endpoint_url=CONF.neutron_url,
            auth_strategy=None, timeout=CONF.neutron_url_timeout)
    return my_client
