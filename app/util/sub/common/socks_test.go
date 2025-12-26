package common

import (
	"testing"

	"github.com/5vnetwork/vx-core/common"
)

var socksLink = "socks5://admin:1111@1.1.1.1:1111"

func TestParseSocksFromLink(t *testing.T) {
	config, err := ParseSocks5FromLink(socksLink)
	common.Must(err)
	t.Log(config)
}
