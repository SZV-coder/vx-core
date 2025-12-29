// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package router

import (
	"context"

	"github.com/5vnetwork/vx-core/common/session"
)

type ConditionFakeIp struct {
}

func (m *ConditionFakeIp) Apply(c context.Context, info *session.Info, rw interface{}) (interface{}, bool) {
	ip := info.GetFakeIP()
	if ip == nil {
		return rw, false
	}
	return rw, true
}
