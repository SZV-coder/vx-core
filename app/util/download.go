// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package util

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/5vnetwork/vx-core/i"
)

func DownloadToMemory(url string, handlers []i.Handler) ([]byte, error) {
	if len(handlers) == 0 {
		return nil, errors.New("no handlers")
	}
	for _, h := range handlers {
		httpClient := HandlerToHttpClient(h)
		rsp, err := httpClient.Get(url)
		if err != nil {
			continue
		}
		defer rsp.Body.Close()
		buffer := &bytes.Buffer{}
		// read body to a buffer
		_, err = io.Copy(buffer, rsp.Body)
		if err != nil {
			continue
		}
		return buffer.Bytes(), nil
	}
	return nil, errors.New("all handlers failed")
}

func DownloadToFile(url string, client *http.Client, dest string) error {
	tmpFileName := dest + ".tmp" + strconv.FormatInt(time.Now().UnixNano(), 36)
	tmp, err := os.Create(tmpFileName)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		tmp.Close()
		if !success {
			os.Remove(tmpFileName)
		}
	}()
	rsp, err := client.Get(url)
	if err != nil {
		return err
	}
	// read body to a file
	_, err = io.Copy(tmp, rsp.Body)
	rsp.Body.Close()
	if err != nil {
		return err
	}
	success = true
	err = tmp.Close()
	if err != nil {
		return err
	}
	return os.Rename(tmpFileName, dest)
}
