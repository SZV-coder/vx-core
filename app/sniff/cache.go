// Copyright 2025 5V Network LLC
// SPDX-License-Identifier: AGPL-3.0

package sniff

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/5vnetwork/vx-core/common/buf"
	"github.com/5vnetwork/vx-core/common/net"
	"github.com/5vnetwork/vx-core/common/net/udp"
)

// Cache, ReadMultiBuffer should be called sequentially.
type CachedConn struct {
	net.Conn

	mb       buf.MultiBuffer
	interval time.Duration
}

// It runs for at most 10 ms
func (r *CachedConn) cache(b []byte) (copied bool, len int, err error) {
	err = r.Conn.SetReadDeadline(time.Now().Add(r.interval))
	if err != nil {
		return false, 0, err
	}
	buffer := buf.New()
	num, err := buffer.ReadOnce(r.Conn)
	r.Conn.SetReadDeadline(time.Time{})

	if err != nil && (errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout")) {
		err = nil
	}

	if num > 0 {
		r.mb = append(r.mb, buffer)
		n := r.mb.Copy(b)
		return true, n, err
	} else {
		buffer.Release()
		return false, 0, err
	}
}

func (r *CachedConn) toConn() net.Conn {
	if r.mb.Len() > 0 {
		return net.NewMbConn(r.Conn, r.mb)
	}
	return r.Conn
}

type CachedRW struct {
	buf.DdlReaderWriter
	mb       buf.MultiBuffer
	interval time.Duration
}

// It runs for at most 10 ms
func (r *CachedRW) read(b []byte) (copied bool, len int, err error) {
	err = r.DdlReaderWriter.SetReadDeadline(time.Now().Add(r.interval))
	if err != nil {
		return false, 0, err
	}
	mb, err := r.DdlReaderWriter.ReadMultiBuffer()
	r.DdlReaderWriter.SetReadDeadline(time.Time{})

	if err != nil && (errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout")) {
		err = nil
	}

	if !mb.IsEmpty() {
		r.mb, _ = buf.MergeMulti(r.mb, mb)
		n := r.mb.Copy(b)
		return true, n, err
	} else {
		return false, 0, err
	}
}

func (r *CachedRW) returnRw() any {
	if r.mb.Len() > 0 {
		return buf.NewSecondDdl(r.DdlReaderWriter, r.mb)
	}
	return r.DdlReaderWriter
}

type CachedDdlPacketConn struct {
	udp.DdlPacketReaderWriter
	packets  []*udp.Packet
	interval time.Duration
}

// It runs for at most 10 ms
func (r *CachedDdlPacketConn) read(b []byte) (copied bool, len int, err error) {
	r.DdlPacketReaderWriter.SetReadDeadline(time.Now().Add(r.interval))
	p, err := r.DdlPacketReaderWriter.ReadPacket()
	r.DdlPacketReaderWriter.SetReadDeadline(time.Time{})
	if p != nil {
		copied := 0
		for _, p := range r.packets {
			n := copy(b, p.Payload.Bytes())
			b = b[n:]
			copied += n
		}
		return true, copied, err
	} else {
		return false, 0, err
	}
}

func (r *CachedDdlPacketConn) returnRw() any {
	if len(r.packets) > 0 {
		return &udp.SecondDdlReaderWriter{
			DdlPacketReaderWriter: r.DdlPacketReaderWriter,
			Packets:               r.packets,
		}
	}
	return r.DdlPacketReaderWriter
}
