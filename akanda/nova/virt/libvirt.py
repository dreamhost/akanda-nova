from nova.virt.libvirt import config
from nova.virt.libvirt import driver

class LibvirtDriver(driver.LibvirtDriver):
    def get_guest_config(self, instance, network_info, image_meta, rescue=None,
                         block_device_info=None):
        guest = super(LibvirtDriver, self).get_guest_config(instance,
                                                            network_info,
                                                            image_meta,
                                                            rescue,
                                                            block_device_info)

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
