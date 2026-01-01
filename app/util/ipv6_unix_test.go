//go:build darwin || linux

package util_test

import (
	"testing"

	"github.com/5vnetwork/vx-core/app/util"
	"github.com/5vnetwork/vx-core/tun"
)

func TestNICSupportIPv6(t *testing.T) {
	device, err := tun.GetPrimaryPhysicalInterface()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("default nic %s", device.Name)
	support6 := util.NICSupportIPv6Index(uint32(device.Index))
	t.Logf("support6: %v", support6)
}

func TestNICHasGlobalIPv6Address(t *testing.T) {
	device, err := tun.GetPrimaryPhysicalInterface()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("default nic %s", device.Name)
	support6, err := util.NICHasGlobalIPv6Address(uint32(device.Index))
	t.Logf("support6: %v", support6)
}
