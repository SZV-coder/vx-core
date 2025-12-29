// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package buildclient

import "github.com/5vnetwork/vx-core/app/configs"

func Wfp(config *configs.WfpConfig, f *Builder) error {
	return nil
}
