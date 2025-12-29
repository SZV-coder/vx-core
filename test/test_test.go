package test

import (
	"context"
	"testing"

	"github.com/5vnetwork/vx-core/app/util"
	"github.com/5vnetwork/vx-core/app/util/downloader"
	"github.com/5vnetwork/vx-core/common"
	"github.com/rs/zerolog/log"
)

func TestSub(t *testing.T) {
	t.Skip()
	content, _, err := downloader.DownloadToMemoryResty(context.Background(),
		"",
		map[string]string{
			"User-Agent": "v2ray-core",
		},
	)
	common.Must(err)
	result, err := util.Decode(string(content))
	common.Must(err)
	log.Print(result)
}

func TestA(t *testing.T) {
	// t.Skip()
}
