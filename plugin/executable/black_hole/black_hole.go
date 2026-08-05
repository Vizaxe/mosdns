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

package black_hole

import (
	"bytes"
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"net/netip"
	"os"
	"strings"
)

const PluginType = "black_hole"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.Executable = (*BlackHole)(nil)

type Args struct {
	Files []string `yaml:"files"`
	Ips   []string `yaml:"ips"`
}

type BlackHole struct {
	logger *zap.Logger
	tag    string
	ipv4   []netip.Addr
	ipv6   []netip.Addr
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewBlackHole(bp.L(), bp.Tag(), args.(*Args))
}

// QuickSetup format: [ipv4|ipv6] ...
// Support both ipv4/a and ipv6/aaaa families.
func QuickSetup(bq sequence.BQ, s string) (any, error) {
	cutPrefix := func(s string, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p), true
		}
		return s, false
	}
	args := new(Args)
	for _, exp := range strings.Fields(s) {
		//if tag, ok := cutPrefix(exp, "$"); ok {
		//	args.DomainSets = append(args.DomainSets, tag)
		//} else
		if path, ok := cutPrefix(exp, "&"); ok {
			args.Files = append(args.Files, path)
		} else {
			args.Ips = append(args.Ips, exp)
		}
	}
	return NewBlackHole(bq.L(), "-", args)
}

// NewBlackHole creates a new BlackHole with given ips.
func NewBlackHole(logger *zap.Logger, tag string, args *Args) (*BlackHole, error) {
	b := &BlackHole{
		logger: logger,
		tag:    tag,
	}

	for _, s := range args.Files {
		ips, err := loadFromFile(s)
		if err != nil {
			return nil, err
		}
		if ips != nil {
			for _, ip := range ips {
				args.Ips = append(args.Ips, ip)
			}
		}
	}

	for _, s := range args.Ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv4 addr %s, %w", s, err)
		}
		if addr.Is4() {
			b.ipv4 = append(b.ipv4, addr)
		} else {
			b.ipv6 = append(b.ipv6, addr)
		}
	}
	return b, nil
}

func loadFromFile(f string) ([]string, error) {
	if len(f) == 0 {
		return nil, fmt.Errorf("empty file path")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read ip file %s: %w", f, err)
	}
	return loadFromReader(bytes.NewReader(b))
}

// Exec implements sequence.Executable. It set a response with given ips if
// query has corresponding qtypes.
func (b *BlackHole) Exec(_ context.Context, qCtx *query_context.Context) error {
	if r := b.Response(qCtx.Q()); r != nil {
		b.logger.Debug("result change", qCtx.InfoField(), zap.Int("rcode", r.Rcode))
		if or := qCtx.R(); or != nil {
			qCtx.SetBlackHoleOrigResp(or)
		}
		qCtx.SetBlackHoleTag(b.tag)
		qCtx.SetResponse(r)
	}
	return nil
}

// Response returns a response with given ips if query has corresponding qtypes.
// Otherwise, it returns nil.
func (b *BlackHole) Response(q *dns.Msg) *dns.Msg {
	if len(q.Question) != 1 {
		return nil
	}

	qName := q.Question[0].Name
	qtype := q.Question[0].Qtype

	switch {
	case qtype == dns.TypeA && len(b.ipv4) > 0:
		r := new(dns.Msg)
		r.SetReply(q)
		for _, addr := range b.ipv4 {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: addr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
		return r

	case qtype == dns.TypeAAAA && len(b.ipv6) > 0:
		r := new(dns.Msg)
		r.SetReply(q)
		for _, addr := range b.ipv6 {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qName,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: addr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
		return r
	}
	return nil
}
