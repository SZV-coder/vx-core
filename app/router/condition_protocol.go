package router

import (
	"context"
	"slices"

	"github.com/5vnetwork/vx-core/app/sniff"
	"github.com/5vnetwork/vx-core/common/session"
)

type ConditionProtocol struct {
	Sniffer *sniff.Sniffer

	protocols []string
}

func (m *ConditionProtocol) Apply(c context.Context, info *session.Info, rw interface{}) (interface{}, bool) {
	if !info.Sniffed && rw != nil {
		rw, _ = m.Sniffer.Sniff(c, info, rw)
	}
	if info.Protocol != "" {
		return rw, slices.Contains(m.protocols, info.Protocol)
	}
	return rw, false
}
