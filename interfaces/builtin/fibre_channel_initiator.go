// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

/*
 * The fibre-channel-initiator interface allows storage orchestration software
 * to discover Fibre Channel initiator and remote-port state and to trigger the
 * SCSI sysfs operations needed after target discovery. It intentionally does
 * not grant raw block devices, SCSI generic devices, multipath control, or
 * mount permissions; those remain covered by their dedicated interfaces.
 */

const fibreChannelInitiatorSummary = `allows Fibre Channel initiator discovery and SCSI host orchestration`

const fibreChannelInitiatorBaseDeclarationPlugs = `
  fibre-channel-initiator:
    allow-installation: false
    deny-auto-connection: true
`

const fibreChannelInitiatorBaseDeclarationSlots = `
  fibre-channel-initiator:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const fibreChannelInitiatorConnectedPlugAppArmor = `
# Fibre Channel initiator and remote-port discovery.
/sys/class/fc_host/{,**} r,
/sys/class/fc_transport/{,**} r,
/sys/class/fc_remote_ports/{,**} r,
/sys/devices/**/fc_host/{,**} r,
/sys/devices/**/fc_transport/{,**} r,
/sys/devices/**/fc_remote_ports/{,**} r,

# Remote-port-backed SCSI topology and device identity.
/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/{,**} r,

# Per-LUN maintenance for FC-backed SCSI devices.
/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/{rescan,delete} rw,
/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/{rescan,delete} ra,

# SCSI host rescans used after Fibre Channel target discovery.
/sys/class/scsi_host/host[0-9]*/scan rw,
/sys/class/scsi_host/host[0-9]*/scan ra,
/sys/devices/**/scsi_host/host[0-9]*/scan rw,
/sys/devices/**/scsi_host/host[0-9]*/scan ra,

# SCSI device rescans used after Fibre Channel volume resize.
/sys/bus/scsi/drivers/sd/[0-9]*:[0-9]*:[0-9]*:[0-9]*/rescan rw,
/sys/class/scsi_device/[0-9]*:[0-9]*:[0-9]*:[0-9]*/device/rescan rw,
/sys/class/scsi_disk/[0-9]*:[0-9]*:[0-9]*:[0-9]*/device/rescan rw,
/sys/block/*/device/rescan rw,
/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/rescan rw,
/sys/devices/**/block/*/device/rescan rw,

# zFCP LUN management on s390x.
/sys/bus/ccw/drivers/zfcp/{,**} r,
/sys/bus/ccw/drivers/zfcp/**/{port_rescan,unit_add,unit_remove} rw,
/sys/bus/ccw/drivers/zfcp/**/{port_rescan,unit_add,unit_remove} ra,
/sys/devices/css[0-9]*/**/{port_rescan,unit_add,unit_remove} rw,
/sys/devices/css[0-9]*/**/{port_rescan,unit_add,unit_remove} ra,

# SCSI block-device metadata and detach control after discovery.
/sys/block/*/device/wwid r,
/sys/block/*/device/delete rw,
/sys/devices/**/block/*/device/wwid r,
/sys/devices/**/block/*/device/delete rw,
/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/wwid r,
/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/delete rw,
/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/wwid r,
`

func init() {
	registerIface(&commonInterface{
		name:                  "fibre-channel-initiator",
		summary:               fibreChannelInitiatorSummary,
		implicitOnClassic:     true,
		baseDeclarationSlots:  fibreChannelInitiatorBaseDeclarationSlots,
		baseDeclarationPlugs:  fibreChannelInitiatorBaseDeclarationPlugs,
		connectedPlugAppArmor: fibreChannelInitiatorConnectedPlugAppArmor,
	})
}
