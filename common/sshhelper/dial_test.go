package sshhelper_test

import (
	"fmt"
	"testing"

	"github.com/5vnetwork/vx-core/common/sshhelper"
)

func TestDial(t *testing.T) {
	t.Skip()
	client, _, err := sshhelper.Dial(&sshhelper.DialConfig{
		Addr:     fmt.Sprintf("%s:%d", "", 22),
		User:     "",
		Password: "",
	})
	if err != nil {
		t.Fatalf("sshhelper.Dial() error: %v", err)
	}
	defer client.Close()
	t.Logf("sshhelper.Dial() success")
}
