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


from nova.virt.libvirt import config
from nova.virt.libvirt import driver


class LibvirtDriver(driver.LibvirtDriver):
    def get_guest_config(self, instance, network_info, image_meta, disk_info,
                         rescue=None, block_device_info=None):
        guest = super(LibvirtDriver, self).get_guest_config(instance,
                                                            network_info,
                                                            image_meta,
                                                            disk_info,
                                                            rescue,
                                                            block_device_info)

        image_meta = image_meta or {}

        if image_meta.get('properties', {}).get('nic_model') == 'e1000':
            for device in guest.devices:
                if isinstance(device, config.LibvirtConfigGuestInterface):
                    device.model = 'e1000'

        if image_meta.get('properties', {}).get('drive_bus') == 'ide':
            for device in guest.devices:
                if isinstance(device, config.LibvirtConfigGuestDisk):
                    if device.target_bus == 'virtio':
                        device.target_bus = 'ide'
                        device.target_dev = 'h' + device.target_dev[1:]

        return guest
