/*
 * Copyright (C) 2024, Vizaxe
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

package dual_stack_ecs_handler

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"net"
	"net/netip"
)

const PluginType = "dual_stack_ecs_handler"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.RecursiveExecutable = (*ECSHandler)(nil)

type Args struct {
	Ipv4  string `yaml:"ipv4"`
	Ipv6  string `yaml:"ipv6"`
	Mask4 int    `yaml:"mask4"`
	Mask6 int    `yaml:"mask6"`
}

type ECSHandler struct {
	args       Args
	ipv4Preset netip.Addr // unmapped
	ipv6Preset netip.Addr // unmapped
}

func NewHandler(args Args) (*ECSHandler, error) {
	var ipv4Preset netip.Addr
	if len(args.Ipv4) > 0 {
		addr, err := netip.ParseAddr(args.Ipv4)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv4 address, %w", err)
		}
		ipv4Preset = addr.Unmap()
		if !checkOrInitMask(&args.Mask4, 0, 32, 24) {
			return nil, fmt.Errorf("invalid mask4")
		}
	} else {
		return nil, fmt.Errorf("invalid ipv4 address, if you are using only ipv6 ecs, please use the ecs_handler plugin")
	}

	var ipv6Preset netip.Addr
	if len(args.Ipv6) > 0 {
		addr, err := netip.ParseAddr(args.Ipv6)
		if err != nil {
			return nil, fmt.Errorf("invalid ipv6 address, %w", err)
		}
		ipv6Preset = addr.Unmap()
		if !checkOrInitMask(&args.Mask6, 0, 128, 48) {
			return nil, fmt.Errorf("invalid mask6")
		}
	} else {
		return nil, fmt.Errorf("invalid ipv6 address, if you are using only ipv4 ecs, please use the ecs_handler plugin")
	}

	return &ECSHandler{args: args, ipv4Preset: ipv4Preset, ipv6Preset: ipv6Preset}, nil
}

func checkOrInitMask(p *int, min, max, defaultM int) bool {
	v := *p
	if v < min || v > max {
		return false
	}
	if v == 0 {
		*p = defaultM
	}
	return true
}

func Init(_ *coremain.BP, args any) (any, error) {
	return NewHandler(*args.(*Args))
}

// Exec tries to append ECS to qCtx.Q().
func (e *ECSHandler) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if err := e.addECS(qCtx); err != nil {
		return err
	}
	err := next.ExecNext(ctx, qCtx)
	if err != nil {
		return err
	}

	return nil
}

// AddECS adds a *dns.EDNS0_SUBNET record to q.
func (e *ECSHandler) addECS(qCtx *query_context.Context) error {
	queryOpt := qCtx.QOpt()

	// Check if query already has an ecs.
	for _, o := range queryOpt.Option {
		if o.Option() == dns.EDNS0SUBNET {
			// skip it
			return nil
		}
	}

	if qCtx.QQuestion().Qclass != dns.ClassINET {
		// RFC 7871 5:
		// ECS is only defined for the Internet (IN) DNS class.
		return nil
	}

	qtype := qCtx.QQuestion().Qtype

	if qtype == dns.TypeA {
		ecs, err := newSubnet(e.ipv4Preset.AsSlice(), uint8(e.args.Mask4), false)
		if err != nil {
			return err
		}
		queryOpt.Option = append(queryOpt.Option, ecs)
	} else if qtype == dns.TypeAAAA {
		ecs, err := newSubnet(e.ipv6Preset.AsSlice(), uint8(e.args.Mask6), true)
		if err != nil {
			return err
		}
		queryOpt.Option = append(queryOpt.Option, ecs)
	} else {
		ecs1, err := newSubnet(e.ipv4Preset.AsSlice(), uint8(e.args.Mask4), false)
		if err != nil {
			return err
		}
		ecs2, err := newSubnet(e.ipv6Preset.AsSlice(), uint8(e.args.Mask6), true)
		if err != nil {
			return err
		}
		queryOpt.Option = append(queryOpt.Option, ecs1, ecs2)
	}
	return nil
}

func newSubnet(ip net.IP, mask uint8, v6 bool) (*dns.EDNS0_SUBNET, error) {
	edns0Subnet := new(dns.EDNS0_SUBNET)
	// edns family: https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	// ipv4 = 1
	// ipv6 = 2
	if !v6 { // ipv4
		edns0Subnet.Family = 1
	} else { // ipv6
		edns0Subnet.Family = 2
	}

	_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), mask))
	if err != nil {
		return nil, fmt.Errorf("failed to parse ecs subnet %s/%d: %w", ip.String(), mask, err)
	}

	edns0Subnet.SourceNetmask = mask
	edns0Subnet.Code = dns.EDNS0SUBNET
	edns0Subnet.Address = ipNet.IP

	// SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
	// number of significant bits of ADDRESS that the response covers.
	// In queries, it MUST be set to 0.
	// https://tools.ietf.org/html/rfc7871
	edns0Subnet.SourceScope = 0
	return edns0Subnet, nil
}
