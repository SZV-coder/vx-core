// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package downloader

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/5vnetwork/vx-core/app/util"
	"github.com/5vnetwork/vx-core/common/net"
	"github.com/5vnetwork/vx-core/common/session"
	"github.com/5vnetwork/vx-core/i"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog/log"
)

type Downloader struct {
	HandlerPicker i.Router
}

func NewDownloader(handlerPicker i.Router) *Downloader {
	return &Downloader{HandlerPicker: handlerPicker}
}

func (d *Downloader) Download(ctx context.Context, u string, headers map[string]string) ([]byte, http.Header, error) {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		return nil, nil, err
	}
	handler, err := d.HandlerPicker.PickHandler(ctx, &session.Info{
		Target: net.Destination{
			Address: net.ParseAddress(parsedUrl.Host),
			Port:    443,
			Network: net.Network_TCP,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return DownloadToMemoryResty(ctx, u, headers, handler)
}

func DownloadToMemoryResty(ctx context.Context,
	url string, headers map[string]string, handlers ...i.Outbound) ([]byte, http.Header, error) {
	if len(handlers) == 0 {
		return nil, nil, errors.New("no handlers")
	}

	for _, h := range handlers {
		client := resty.New()
		client.SetTransport(util.HandlerToHttpClient(h).Transport)

		req := client.R().SetContext(ctx).EnableTrace()

		// Apply custom headers if provided
		for key, value := range headers {
			req.SetHeader(key, value)
		}

		resp, err := req.Get(url)
		if err != nil {
			log.Err(err).Str("handler", h.Tag()).Msg("DownloadToMemoryResty handler failed")
			continue
		}
		return resp.Body(), resp.Header(), nil
	}
	return nil, nil, errors.New("all handlers failed")
}

type Downloader0 struct {
	handlers []i.Outbound
}

func NewDownloader0(handlers []i.Outbound) *Downloader0 {
	return &Downloader0{handlers: handlers}
}

func (d *Downloader0) Download(ctx context.Context, url string, headers map[string]string) ([]byte, http.Header, error) {
	return DownloadToMemoryResty(ctx, url, headers, d.handlers...)
}
