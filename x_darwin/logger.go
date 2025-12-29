// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

//go:build darwin

package x_darwin

import (
	"github.com/5vnetwork/vx-core/common/redirect"
)

func RedirectStderr(path string) error {
	return redirect.RedirectStderr(path)
}
