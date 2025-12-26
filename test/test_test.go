package test

import (
	"context"
	"testing"

	"github.com/5vnetwork/vx-core/app/util"
	"github.com/5vnetwork/vx-core/app/util/downloader"
	"github.com/5vnetwork/vx-core/common"
	"github.com/5vnetwork/vx-core/proxy/freedom"
	"github.com/5vnetwork/vx-core/transport"
	"github.com/rs/zerolog/log"
)

func TestSub(t *testing.T) {
	t.Skip()
	content, _, err := downloader.DownloadToMemoryResty(context.Background(),
		"",
		freedom.New(transport.DefaultDialer, transport.DefaultPacketListener, "", nil),
	)
	common.Must(err)
	result, err := util.Decode(string(content))
	common.Must(err)
	log.Print(result)
}

func TestA(t *testing.T) {
	// t.Skip()
}
