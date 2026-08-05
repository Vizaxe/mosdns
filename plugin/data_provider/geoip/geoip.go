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

package geoip

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geofile"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"go.uber.org/zap"
)

const PluginType = "geoip"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewV2rayGeoip(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	Ips   []string `yaml:"ips"`
	Watch bool     `yaml:"watch"`
}

var _ data_provider.IPMatcherProvider = (*V2rayGeoip)(nil)

type V2rayGeoip struct {
	mu sync.RWMutex
	mg []netlist.Matcher

	watch  bool
	ips    []string
	logger *zap.Logger
	cancel context.CancelFunc
}

func (d *V2rayGeoip) GetIPMatcher() netlist.Matcher {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return MatcherGroup(d.mg)
}

func NewV2rayGeoip(bp *coremain.BP, args *Args) (*V2rayGeoip, error) {
	v := &V2rayGeoip{
		watch:  args.Watch,
		ips:    args.Ips,
		logger: bp.L(),
	}

	mg, err := loadGeoipMatchers(args.Ips)
	if err != nil {
		return nil, err
	}
	v.mg = mg

	if args.Watch {
		v.startWatchers()
	}

	return v, nil
}

func loadGeoipMatchers(ips []string) ([]netlist.Matcher, error) {
	var mg []netlist.Matcher

	fileCodes := make(map[string][]string)
	var ipEntries []string
	for _, item := range ips {
		if strings.Count(item, ":") == 1 {
			split := strings.SplitN(item, ":", 2)
			fileCodes[split[0]] = append(fileCodes[split[0]], split[1])
		} else {
			ipEntries = append(ipEntries, item)
		}
	}

	for file, codes := range fileCodes {
		l := netlist.NewList()
		for _, code := range codes {
			if err := LoadFile(file, code, l); err != nil {
				return nil, err
			}
		}
		if l.Len() > 0 {
			l.Sort()
			mg = append(mg, l)
		}
	}

	if len(ipEntries) > 0 {
		l := netlist.NewList()
		if err := ip_set.LoadFromIPs(ipEntries, l); err != nil {
			return nil, err
		}
		if l.Len() > 0 {
			l.Sort()
			mg = append(mg, l)
		}
	}

	return mg, nil
}

func (d *V2rayGeoip) startWatchers() {
	fileSet := make(map[string]struct{})
	for _, item := range d.ips {
		if strings.Count(item, ":") == 1 {
			split := strings.SplitN(item, ":", 2)
			fileSet[split[0]] = struct{}{}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel

	for filePath := range fileSet {
		path := filePath
		go func() {
			if err := geofile.WatchFile(ctx, d.logger, path, func() error {
				return d.reload()
			}); err != nil && err != context.Canceled {
				d.logger.Error("file watcher stopped unexpectedly", zap.String("file", path), zap.Error(err))
			}
		}()
	}
}

func (d *V2rayGeoip) reload() error {
	newMg, err := loadGeoipMatchers(d.ips)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.mg = newMg
	d.mu.Unlock()
	return nil
}

func (d *V2rayGeoip) Close() error {
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

func LoadFile(file string, code string, l *netlist.List) error {
	if len(file) > 0 {
		cidrs, err := geofile.LoadIP(file, code)
		if err != nil {
			return err
		}
		if cidrs == nil || len(cidrs) == 0 {
			return fmt.Errorf("%s not found in %s", code, file)
		}
		for i, cidr := range cidrs {
			ip, ok := netip.AddrFromSlice(cidr.Ip)
			if !ok {
				return fmt.Errorf("invalid ip at index #%d, %s", i, cidr.Ip)
			}
			prefix, err := ip.Prefix(int(cidr.Prefix))
			if err != nil {
				return fmt.Errorf("invalid prefix at index #%d, %w", i, err)
			}
			l.Append(prefix)
		}
	}
	return nil
}

type MatcherGroup []netlist.Matcher

func (mg MatcherGroup) Match(addr netip.Addr) bool {
	for _, m := range mg {
		if m.Match(addr) {
			return true
		}
	}
	return false
}
