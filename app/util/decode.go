package util

import (
	"github.com/5vnetwork/vx-core/app/util/sub"
	"github.com/5vnetwork/vx-core/app/util/sub/clash"
	"github.com/5vnetwork/vx-core/app/util/sub/common"
)

func Decode(content string) (*sub.DecodeResult, error) {
	result, err := clash.ParseClashConfig([]byte(content))
	if err != nil {
		return common.DecodeCommon(content)
	}
	return result, nil
}
