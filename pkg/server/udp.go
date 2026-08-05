/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type UDPServerOpts struct {
	Logger *zap.Logger

	// MaxConcurrentQueries limits concurrent queries across all connections.
	// 0 or negative means defaultMaxConcurrentQueries.
	MaxConcurrentQueries int
}

// ServeUDP starts a server at c. It returns if c had a read error.
// It always returns a non-nil error.
// h is required. logger is optional.
func ServeUDP(c *net.UDPConn, h Handler, opts UDPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}

	maxConcurrent := opts.MaxConcurrentQueries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentQueries
	}
	sem := make(chan struct{}, maxConcurrent)

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errListenerCtxCanceled)

	rb := pool.GetBuf(dns.MaxMsgSize)
	defer pool.ReleaseBuf(rb)

	oobReader, oobWriter, err := initOobHandler(c)
	if err != nil {
		return fmt.Errorf("failed to init oob handler, %w", err)
	}
	var ob []byte
	if oobReader != nil {
		obp := pool.GetBuf(1024)
		defer pool.ReleaseBuf(obp)
		ob = *obp
	}

	for {
		n, oobn, _, remoteAddr, err := c.ReadMsgUDPAddrPort(*rb, ob)
		if err != nil {
			if n == 0 {
				// Err with zero read. Most likely because c was closed.
				return fmt.Errorf("unexpected read err: %w", err)
			}
			// Temporary err.
			logger.Warn("read err", zap.Error(err))
			continue
		}

		q := new(dns.Msg)
		if err := q.Unpack((*rb)[:n]); err != nil {
			logger.Warn("invalid msg", zap.Error(err), zap.Binary("msg", (*rb)[:n]), zap.Stringer("from", remoteAddr))
			continue
		}

		var dstIpFromCm net.IP
		if oobReader != nil {
			var err error
			dstIpFromCm, err = oobReader(ob[:oobn])
			if err != nil {
				logger.Error("failed to get dst address from oob", zap.Error(err))
			}
		}

		// 非阻塞获取信号量，超过并发上限时丢弃请求
		select {
		case sem <- struct{}{}:
		default:
			logger.Warn("too many concurrent queries, drop", zap.Stringer("from", remoteAddr))
			continue
		}

		// handle query
		go func() {
			defer func() { <-sem }()
			payload := h.Handle(listenerCtx, q, QueryMeta{ClientAddr: remoteAddr.Addr(), Protocol: "UDP"}, pool.PackBuffer)
			if payload == nil {
				return
			}
			defer pool.ReleaseBuf(payload)

			var oob []byte
			if oobWriter != nil && dstIpFromCm != nil {
				oob = oobWriter(dstIpFromCm)
			}
			if _, _, err := c.WriteMsgUDPAddrPort(*payload, oob, remoteAddr); err != nil {
				logger.Debug("failed to write response", zap.Stringer("client", remoteAddr), zap.Error(err))
			}
		}()
	}
}

type getSrcAddrFromOOB func(oob []byte) (net.IP, error)
type writeSrcAddrToOOB func(a net.IP) []byte

// ServeUnix starts a server at c. It returns if c had a read error.
// It always returns a non-nil error.
// h is required. logger is optional.
func ServeUnix(c *net.UnixConn, h Handler, opts UDPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}

	maxConcurrent := opts.MaxConcurrentQueries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentQueries
	}
	sem := make(chan struct{}, maxConcurrent)

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errListenerCtxCanceled)

	rb := pool.GetBuf(dns.MaxMsgSize)
	defer pool.ReleaseBuf(rb)

	buf := *rb

	for {
		n, addr, err := c.ReadFromUnix(buf)
		if err != nil {
			if n == 0 {
				return fmt.Errorf("unexpected read err: %w", err)
			}
			// Temporary err.
			logger.Warn("read err", zap.Error(err))
			continue
		}

		q := new(dns.Msg)
		if err := q.Unpack(buf[:n]); err != nil {
			logger.Warn("invalid msg", zap.Error(err), zap.Binary("msg", buf[:n]))
			continue
		}

		if addr == nil {
			logger.Warn("missing client addr, drop query")
			continue
		}

		select {
		case sem <- struct{}{}:
		default:
			logger.Warn("too many concurrent queries, drop", zap.Stringer("from", addr))
			continue
		}

		// handle query
		go func() {
			defer func() { <-sem }()
			payload := h.Handle(listenerCtx, q, QueryMeta{ClientAddr: netip.Addr{}, Protocol: "unixgram"}, pool.PackBuffer)
			if payload == nil {
				return
			}
			defer pool.ReleaseBuf(payload)
			if _, err := c.WriteToUnix(*payload, addr); err != nil {
				logger.Warn("failed to write response", zap.Error(err))
			}
		}()
	}
}
