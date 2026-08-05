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

package quic_server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/server"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/server/server_utils"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
)

const PluginType = "quic_server"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

type Args struct {
	Entry       string   `yaml:"entry"`
	Listen      []string `yaml:"listen"`
	Cert        string   `yaml:"cert"`
	Key         string   `yaml:"key"`
	IdleTimeout int      `yaml:"idle_timeout"`
}

func (a *Args) init() {
	utils.SetDefaultNum(&a.IdleTimeout, 30)
}

type QuicServer struct {
	args *Args
	ls   []*quic.Listener
	ts   []*quic.Transport
}

func (s *QuicServer) Close() error {
	var err error
	for _, l := range s.ls {
		if e := l.Close(); e != nil {
			err = e
		}
	}
	for _, t := range s.ts {
		if e := t.Close(); e != nil {
			err = e
		}
	}
	return err
}

func Init(bp *coremain.BP, args any) (any, error) {
	return StartServer(bp, args.(*Args))
}

func StartServer(bp *coremain.BP, args *Args) (*QuicServer, error) {
	logger := bp.L()

	dh, err := server_utils.NewHandler(bp, args.Entry)
	if err != nil {
		return nil, fmt.Errorf("failed to init dns handler, %w", err)
	}

	// Init tls
	if len(args.Key) == 0 || len(args.Cert) == 0 {
		return nil, errors.New("quic server requires a tls certificate")
	}
	tlsConfig := new(tls.Config)
	if err := server.LoadCert(tlsConfig, args.Cert, args.Key); err != nil {
		return nil, fmt.Errorf("failed to read tls cert, %w", err)
	}
	tlsConfig.NextProtos = []string{"doq"}

	idleTimeout := time.Duration(args.IdleTimeout) * time.Second

	quicConfig := &quic.Config{
		MaxIdleTimeout:                 idleTimeout,
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024,
		Allow0RTT:                      false,

		// UniStream is not allowed.
		MaxIncomingUniStreams: -1,

		// 限制单连接上的并发双向 stream 数，防止恶意客户端
		// 在单条连接上打开大量 stream 消耗服务端资源。
		// server 层另有全局并发信号量（defaultMaxConcurrentQueries）兜底。
		MaxIncomingStreams: 256,
	}

	srk, _, err := utils.InitQUICSrkFromIfaceMac()
	if err != nil {
		logger.Warn("failed to init quic stateless reset key, it will be disabled", zap.Error(err))
	}

	serverOpts := server.DoQServerOpts{Logger: bp.L(), IdleTimeout: idleTimeout}

	var ls []*quic.Listener
	var ts []*quic.Transport

	for _, listenAddr := range args.Listen {
		uc, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			for _, ll := range ls {
				ll.Close()
			}
			for _, tt := range ts {
				tt.Close()
			}
			return nil, fmt.Errorf("failed to listen socket on %s, %w", listenAddr, err)
		}

		qt := &quic.Transport{
			Conn:              uc,
			StatelessResetKey: (*quic.StatelessResetKey)(srk),
		}

		quicListener, err := qt.Listen(tlsConfig, quicConfig)
		if err != nil {
			qt.Close()
			for _, ll := range ls {
				ll.Close()
			}
			for _, tt := range ts {
				tt.Close()
			}
			return nil, fmt.Errorf("failed to listen quic on %s, %w", listenAddr, err)
		}
		bp.L().Info("quic server started", zap.Stringer("addr", quicListener.Addr()))

		ls = append(ls, quicListener)
		ts = append(ts, qt)

		go func(l *quic.Listener) {
			defer l.Close()
			err := server.ServeDoQ(l, dh, serverOpts)
			bp.M().GetSafeClose().SendCloseSignal(err)
		}(quicListener)
	}

	return &QuicServer{
		args: args,
		ls:   ls,
		ts:   ts,
	}, nil
}
