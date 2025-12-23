//go:build !server

package dispatcher

import (
	"context"
	"strings"

	"github.com/5vnetwork/vx-core/common/appid"
	"github.com/5vnetwork/vx-core/common/session"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func (d *Dispatcher) recordlinkStats(ctx context.Context, info *session.Info) {
}

// for debug purpose
func (p *Dispatcher) populateAppId(ctx context.Context, info *session.Info) {
	if info.AppId == "" {
		if (zerolog.GlobalLevel() == zerolog.DebugLevel) &&
			(!strings.Contains(info.InboundTag, "dns")) &&
			!strings.Contains(info.InboundTag, "DNS") {
			appId, err := appid.GetAppId(ctx, info.Source, &info.Target)
			if err != nil {
				log.Ctx(ctx).Debug().Err(err).Msg("failed to get appId")
			}
			info.AppId = appId
		}
	}
}
