// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package proxy

import "github.com/5vnetwork/vx-core/i"

type withHandler interface {
	WithHandler(h i.Handler)
}

type withTimeoutPolicy interface {
	WithTimeoutPolicy(tp i.TimeoutSetting)
}

type withOnUnauthorizedRequest interface {
	WithOnUnauthorizedRequest(f i.UnauthorizedReport)
}
