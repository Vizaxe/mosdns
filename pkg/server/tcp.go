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
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	defaultTCPIdleTimeout       = time.Second * 10
	tcpFirstReadTimeout         = time.Second * 2
	defaultMaxConcurrentQueries = 1000
)

type TCPServerOpts struct {
	// Nil logger == nop
	Logger *zap.Logger

	// Default is defaultTCPIdleTimeout.
	IdleTimeout time.Duration

	// MaxConcurrentQueries limits concurrent queries across all connections.
	// 0 or negative means defaultMaxConcurrentQueries.
	MaxConcurrentQueries int
}

// ServeTCP starts a server at l. It returns if l had an Accept() error.
// It always returns a non-nil error.
func ServeTCP(l net.Listener, h Handler, opts TCPServerOpts) error {
	logger := opts.Logger
	if logger == nil {
		logger = nopLogger
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	firstReadTimeout := tcpFirstReadTimeout
	if idleTimeout < firstReadTimeout {
		firstReadTimeout = idleTimeout
	}

	maxConcurrent := opts.MaxConcurrentQueries
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentQueries
	}
	sem := make(chan struct{}, maxConcurrent)

	listenerCtx, cancel := context.WithCancelCause(context.Background())
	defer cancel(errListenerCtxCanceled)
	for {
		c, err := l.Accept()
		if err != nil {
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// handle connection
		tcpConnCtx, cancelConn := context.WithCancelCause(listenerCtx)
		go func() {
			defer c.Close()
			defer cancelConn(errConnectionCtxCanceled)

			// Try to get server name from tls conn once per connection.
			var serverName string
			var proto = "TCP"
			if tlsConn, ok := c.(*tls.Conn); ok {
				serverName = tlsConn.ConnectionState().ServerName
				proto = "TLS"
			}

			var writeMu sync.Mutex
			firstRead := true
			for {
				if firstRead {
					firstRead = false
					c.SetReadDeadline(time.Now().Add(firstReadTimeout))
				} else {
					c.SetReadDeadline(time.Now().Add(idleTimeout))
				}
				req, _, err := dnsutils.ReadMsgFromTCP(c)
				if err != nil {
					return // read err, close the connection
				}

				// handle query
				go func() {
					// 非阻塞获取信号量，防止 goroutine 无限增长
					select {
					case sem <- struct{}{}:
					default:
						// 达到并发上限，快速拒绝
						resp := new(dns.Msg)
						resp.SetReply(req)
						resp.Rcode = dns.RcodeServerFailure
						resp.RecursionAvailable = true
						payload, _ := pool.PackTCPBuffer(resp)
						if payload != nil {
							writeMu.Lock()
							_, _ = c.Write(*payload)
							writeMu.Unlock()
							pool.ReleaseBuf(payload)
						}
						return
					}

					var clientAddr netip.Addr
					ta, ok := c.RemoteAddr().(*net.TCPAddr)
					if ok {
						clientAddr = ta.AddrPort().Addr()
					}
					r := h.Handle(tcpConnCtx, req, QueryMeta{ClientAddr: clientAddr, ServerName: serverName, Protocol: proto}, pool.PackTCPBuffer)
					if r == nil {
						<-sem // 释放信号量
						// EntryHandler 返回 nil 说明查询不合法或内部打包错误。
						// 跳过该查询的响应，但不关闭整个连接，避免影响同连接上其他正在处理的查询。
						return
					}
					// 用 defer 归还信号量，Handle 内 panic 时也能归还，避免并发名额永久泄漏。
					defer func() { <-sem }()
					defer pool.ReleaseBuf(r)

					writeMu.Lock()
					_, err := c.Write(*r)
					writeMu.Unlock()
					if err != nil {
						// 连接已断开时的写失败是预期行为，降为 Debug 避免日志噪音
						logger.Debug("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
						return
					}
				}()
			}
		}()
	}
}
