// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package inboundcommon

import (
	"github.com/5vnetwork/vx-core/common/buf"
)

type Rejector interface {
	// return a reject packet or nil. p should contains at least network header and transport header
	Reject(p []byte) *buf.Buffer
}
