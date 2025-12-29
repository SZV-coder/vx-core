// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package router

type route struct {
	outboundGroupTags []string
	outboundTag       string
}

func (r *route) GetOutboundGroupTags() []string {
	return r.outboundGroupTags
}

func (r *route) GetOutboundTag() string {
	return r.outboundTag
}
