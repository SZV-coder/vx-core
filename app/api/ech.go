package api

import (
	"context"

	"github.com/5vnetwork/vx-core/app/util"
)

func (a *Api) GenerateECH(ctx context.Context, req *GenerateECHRequest) (*GenerateECHResponse, error) {
	echConfig, echKey, err := util.ExecuteECH(req.Domain)
	if err != nil {
		return nil, err
	}
	return &GenerateECHResponse{
		Config: echConfig,
		Key:    echKey,
	}, nil
}
