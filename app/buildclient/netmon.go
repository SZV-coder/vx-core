// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package buildclient

import (
	"fmt"
	"reflect"

	"github.com/5vnetwork/vx-core/app/client"
	"github.com/5vnetwork/vx-core/app/configs"
	"github.com/5vnetwork/vx-core/common"
	"github.com/5vnetwork/vx-core/i"
)

func Netmon(config *configs.TmConfig, builder *Builder, client *client.Client) error {
	if netmon := builder.getFeature(reflect.TypeOf((*i.DefaultInterfaceInfo)(nil)).Elem()); netmon != nil {
		client.NetMon = netmon.(i.DefaultInterfaceInfo)
		return nil
	}

	// monitor
	monitor, err := NewInterfaceMonotor(config.GetTun().GetDevice().GetName(), builder)
	if err != nil {
		return fmt.Errorf("failed to create tun interface monitor: %w", err)
	}
	client.NetMon = monitor
	common.Must(builder.addComponent(monitor))
	return nil
}
