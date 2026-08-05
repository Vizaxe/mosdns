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

package geosite

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/geofile"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/domain_set"
	"go.uber.org/zap"
)

const PluginType = "geosite"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

func Init(bp *coremain.BP, args any) (any, error) {
	m, err := NewV2rayGeosite(bp, args.(*Args))
	if err != nil {
		return nil, err
	}
	return m, nil
}

type Args struct {
	Domains []string `yaml:"domains"`
	Watch   bool     `yaml:"watch"`
}

var _ data_provider.DomainMatcherProvider = (*V2rayGeosite)(nil)

type V2rayGeosite struct {
	mu sync.RWMutex
	mg []domain.Matcher[struct{}]

	watch   bool
	domains []string
	logger  *zap.Logger
	cancel  context.CancelFunc
}

func (d *V2rayGeosite) GetDomainMatcher() domain.Matcher[struct{}] {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return MatcherGroup(d.mg)
}

func NewV2rayGeosite(bp *coremain.BP, args *Args) (*V2rayGeosite, error) {
	v := &V2rayGeosite{
		watch:   args.Watch,
		domains: args.Domains,
		logger:  bp.L(),
	}

	mg, err := loadGeositeMatchers(args.Domains)
	if err != nil {
		return nil, err
	}
	v.mg = mg

	if args.Watch {
		v.startWatchers()
	}

	return v, nil
}

func loadGeositeMatchers(domains []string) ([]domain.Matcher[struct{}], error) {
	var mg []domain.Matcher[struct{}]

	fileCodes := make(map[string][]string)
	var exps []string
	for _, item := range domains {
		if !strings.Contains(item, ":") {
			exps = append(exps, item)
			continue
		}
		split := strings.SplitN(item, ":", 2)
		switch split[0] {
		case "domain", "full", "regex", "keyword":
			exps = append(exps, item)
		default:
			fileCodes[split[0]] = append(fileCodes[split[0]], split[1])
		}
	}

	for file, codes := range fileCodes {
		m := domain.NewDomainMixMatcher()
		for _, code := range codes {
			if err := LoadFile(file, code, m); err != nil {
				return nil, err
			}
		}
		if m.Len() > 0 {
			mg = append(mg, m)
		}
	}

	if len(exps) > 0 {
		m := domain.NewDomainMixMatcher()
		if err := domain_set.LoadExps(exps, m); err != nil {
			return nil, err
		}
		if m.Len() > 0 {
			mg = append(mg, m)
		}
	}

	return mg, nil
}

func (d *V2rayGeosite) startWatchers() {
	fileSet := make(map[string]struct{})
	for _, item := range d.domains {
		if !strings.Contains(item, ":") {
			continue
		}
		split := strings.SplitN(item, ":", 2)
		switch split[0] {
		case "domain", "full", "regex", "keyword":
		default:
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

func (d *V2rayGeosite) reload() error {
	newMg, err := loadGeositeMatchers(d.domains)
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.mg = newMg
	d.mu.Unlock()
	return nil
}

func (d *V2rayGeosite) Close() error {
	if d.cancel != nil {
		d.cancel()
	}
	return nil
}

func LoadFile(file string, code string, m *domain.MixMatcher[struct{}]) error {
	if len(file) > 0 {
		domains, err := geofile.LoadSite(file, code)
		if err != nil {
			return err
		}
		if domains == nil || len(domains) == 0 {
			return fmt.Errorf("%s not found in %s", code, file)
		}
		for _, dom := range domains {
			var pattern = dom.Value
			switch dom.Type {
			case geofile.Domain_Full:
				pattern = domain.MatcherFull + ":" + pattern
			case geofile.Domain_Domain:
				pattern = domain.MatcherDomain + ":" + pattern
			case geofile.Domain_Regex:
				pattern = domain.MatcherRegexp + ":" + pattern
			case geofile.Domain_Plain:
				pattern = domain.MatcherKeyword + ":" + pattern
			default:
				continue
			}
			if err := m.Add(pattern, struct{}{}); err != nil {
				return err
			}
		}
	}
	return nil
}

type MatcherGroup []domain.Matcher[struct{}]

func (mg MatcherGroup) Match(s string) (struct{}, bool) {
	for _, m := range mg {
		if _, ok := m.Match(s); ok {
			return struct{}{}, true
		}
	}
	return struct{}{}, false
}
