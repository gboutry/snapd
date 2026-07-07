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

package builtin_test

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/kmod"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type fibreChannelInitiatorInterfaceSuite struct {
	iface    interfaces.Interface
	slotInfo *snap.SlotInfo
	slot     *interfaces.ConnectedSlot
	plugInfo *snap.PlugInfo
	plug     *interfaces.ConnectedPlug
}

const fibreChannelInitiatorMockPlugSnapInfoYaml = `name: other
version: 1.0
apps:
 app:
  command: foo
  plugs: [fibre-channel-initiator]
`

const fibreChannelInitiatorCoreYaml = `name: core
version: 0
type: os
slots:
  fibre-channel-initiator:
`

var _ = Suite(&fibreChannelInitiatorInterfaceSuite{
	iface: builtin.MustInterface("fibre-channel-initiator"),
})

func (s *fibreChannelInitiatorInterfaceSuite) SetUpTest(c *C) {
	s.slot, s.slotInfo = MockConnectedSlot(c, fibreChannelInitiatorCoreYaml, nil, "fibre-channel-initiator")
	s.plug, s.plugInfo = MockConnectedPlug(c, fibreChannelInitiatorMockPlugSnapInfoYaml, nil, "fibre-channel-initiator")
}

func (s *fibreChannelInitiatorInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "fibre-channel-initiator")
}

func (s *fibreChannelInitiatorInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.slotInfo), IsNil)
}

func (s *fibreChannelInitiatorInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *fibreChannelInitiatorInterfaceSuite) TestStaticInfo(c *C) {
	si := interfaces.StaticInfoOf(s.iface)
	c.Assert(si.ImplicitOnCore, Equals, false)
	c.Assert(si.ImplicitOnClassic, Equals, true)
	c.Assert(si.Summary, Equals, `allows Fibre Channel initiator discovery and SCSI host orchestration`)
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "fibre-channel-initiator")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "slot-snap-type:")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "- core")
	c.Assert(si.BaseDeclarationSlots, testutil.Contains, "deny-auto-connection: true")
	c.Assert(si.BaseDeclarationPlugs, testutil.Contains, "fibre-channel-initiator")
	c.Assert(si.BaseDeclarationPlugs, testutil.Contains, "allow-installation: false")
	c.Assert(si.BaseDeclarationPlugs, testutil.Contains, "deny-auto-connection: true")
}

func (s *fibreChannelInitiatorInterfaceSuite) TestConnectedPlugSnippet(c *C) {
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	apparmorSpec := apparmor.NewSpecification(appSet)
	c.Assert(apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(apparmorSpec.SecurityTags(), DeepEquals, []string{"snap.other.app"})
	snippet := apparmorSpec.SnippetForTag("snap.other.app")

	c.Assert(snippet, testutil.Contains, "/sys/class/fc_host/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/class/fc_transport/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/class/fc_remote_ports/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/fc_host/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/fc_transport/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/fc_remote_ports/{,**} r,")

	c.Assert(snippet, testutil.Contains, "/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/{rescan,delete} rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/{rescan,delete} ra,")

	c.Assert(snippet, testutil.Contains, "/sys/class/scsi_host/host[0-9]*/scan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/class/scsi_host/host[0-9]*/scan ra,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/scsi_host/host[0-9]*/scan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/scsi_host/host[0-9]*/scan ra,")

	c.Assert(snippet, testutil.Contains, "/sys/bus/scsi/drivers/sd/[0-9]*:[0-9]*:[0-9]*:[0-9]*/rescan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/class/scsi_device/[0-9]*:[0-9]*:[0-9]*:[0-9]*/device/rescan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/class/scsi_disk/[0-9]*:[0-9]*:[0-9]*:[0-9]*/device/rescan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/block/*/device/rescan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/rescan rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/block/*/device/rescan rw,")

	c.Assert(snippet, testutil.Contains, "/sys/bus/ccw/drivers/zfcp/{,**} r,")
	c.Assert(snippet, testutil.Contains, "/sys/bus/ccw/drivers/zfcp/**/{port_rescan,unit_add,unit_remove} rw,")
	c.Assert(snippet, testutil.Contains, "/sys/bus/ccw/drivers/zfcp/**/{port_rescan,unit_add,unit_remove} ra,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/css[0-9]*/**/{port_rescan,unit_add,unit_remove} rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/css[0-9]*/**/{port_rescan,unit_add,unit_remove} ra,")

	c.Assert(snippet, testutil.Contains, "/sys/block/*/device/wwid r,")
	c.Assert(snippet, testutil.Contains, "/sys/block/*/device/delete rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/block/*/device/wwid r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/block/*/device/delete rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/wwid r,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/delete rw,")
	c.Assert(snippet, testutil.Contains, "/sys/devices/**/rport-[0-9]*:[0-9]*-[0-9]*/**/[0-9]*:[0-9]*:[0-9]*:[0-9]*/wwid r,")
}

func (s *fibreChannelInitiatorInterfaceSuite) TestConnectedPlugSnippetDoesNotGrantAdjacentStorageAccess(c *C) {
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)
	apparmorSpec := apparmor.NewSpecification(appSet)
	c.Assert(apparmorSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	snippet := apparmorSpec.SnippetForTag("snap.other.app")

	c.Assert(snippet, Not(testutil.Contains), "/dev/sg")
	c.Assert(snippet, Not(testutil.Contains), "/dev/sd")
	c.Assert(snippet, Not(testutil.Contains), "/dev/disk")
	c.Assert(snippet, Not(testutil.Contains), "/dev/mapper")
	c.Assert(snippet, Not(testutil.Contains), "multipathd")
	c.Assert(snippet, Not(testutil.Contains), "issue_lip")
}

func (s *fibreChannelInitiatorInterfaceSuite) TestOnlyAppArmorSecuritySystem(c *C) {
	appSet, err := interfaces.NewSnapAppSet(s.plug.Snap(), nil)
	c.Assert(err, IsNil)

	// This interface grants sysfs orchestration only. There are no device nodes
	// to tag and no modules or syscall policy are needed.
	udevSpec := udev.NewSpecification(appSet)
	c.Assert(udevSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(udevSpec.Snippets(), HasLen, 0)

	kmodSpec := &kmod.Specification{}
	c.Assert(kmodSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(kmodSpec.Modules(), HasLen, 0)

	seccompSpec := seccomp.NewSpecification(appSet)
	c.Assert(seccompSpec.AddConnectedPlug(s.iface, s.plug, s.slot), IsNil)
	c.Assert(seccompSpec.Snippets(), HasLen, 0)
}

func (s *fibreChannelInitiatorInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
