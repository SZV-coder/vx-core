package sshhelper_test

import (
	"testing"

	"github.com/5vnetwork/vx-core/test"
)

func TestEnableBbr(t *testing.T) {
	t.Skip()
	test.LoadEnvVariables("../../.env")
	client, err := test.GetTestSshClientLocal()
	if err != nil {
		t.Fatalf("server.Dial() error: %v", err)
	}
	defer client.Close()
	err = client.EnableBbr()
	if err != nil {
		t.Fatalf("sshhelper.EnableBbr() error: %v", err)
	}
	t.Logf("sshhelper.EnableBbr() success")
}
