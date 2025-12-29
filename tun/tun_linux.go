// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

//go:build linux && !android

package tun

import (
	"github.com/5vnetwork/vx-core/common/buf"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/tun"
	gtun "gvisor.dev/gvisor/pkg/tcpip/link/tun"
)

type tunWrapper struct {
	device tun.Device
	name   string
}

func NewTun(name string) (TunDevice, error) {
	fd, err := gtun.Open(name)
	if err != nil {
		return nil, err
	}
	device, name, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		return nil, err
	}
	log.Info().Int("fd", fd).Str("name", name).Msg("fd")
	t := &tunWrapper{
		device: device,
		name:   name,
	}
	return t, nil
}

func (t *tunWrapper) Close() error {
	return t.device.Close()
}

func (t *tunWrapper) WritePacket(pkt *buf.Buffer) error {
	defer pkt.Release()
	_, err := t.device.Write([][]byte{pkt.Bytes()}, 0)
	if err != nil {
		return err
	}
	return nil
}

func (t *tunWrapper) ReadPacket() (*buf.Buffer, error) {
	b := buf.New()
	bufs := make([][]byte, 1)
	bufs[0] = b.BytesTo(b.Cap())
	sizes := []int{0}

	_, err := t.device.Read(bufs, sizes, 0)
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Extend(int32(sizes[0]))
	return b, nil
}

func (t *tunWrapper) Name() string {
	return t.name
}

func (t *tunWrapper) Start() error {
	return nil
}
