package util_test

import (
	"context"
	"testing"

	"github.com/5vnetwork/vx-core/app/util"
	"github.com/5vnetwork/vx-core/proxy/freedom"
	"github.com/5vnetwork/vx-core/transport"
)

func TestIpv6(t *testing.T) {
	handler := freedom.New(transport.DefaultDialer, transport.DefaultPacketListener, "freedom", nil)
	response, err := util.TestIpv6(context.Background(), handler, util.AliDNS6)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(response)
}
