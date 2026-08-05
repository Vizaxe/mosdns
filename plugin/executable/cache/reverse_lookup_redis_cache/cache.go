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

package reverse_lookup_redis_cache

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend/redis_cache_backend"
	"github.com/miekg/dns"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	PluginType = "reverse_lookup_redis_cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

const (
	defaultLazyUpdateTimeout = time.Second * 5
	expiredMsgTtl            = 5
)

var _ sequence.RecursiveExecutable = (*ReverseLookupRedisCache)(nil)

var (
	tagNameMapMu sync.Mutex
	TagNameMap   = make(map[string]*ReverseLookupRedisCache)
)

type Args struct {
	Url          string `yaml:"url"`
	RedisTimeout int    `yaml:"redis_timeout"`
	LazyCacheTTL int    `yaml:"lazy_cache_ttl"`

	Separator string `yaml:"separator"`
	Prefix    string `yaml:"prefix"`

	ReadOnly bool `yaml:"read_only"`
}

func (a *Args) init() {
	if len(a.Separator) == 0 {
		a.Separator = ":"
	}
}

type ReverseLookupRedisCache struct {
	args *Args

	logger       *zap.Logger
	backend      cache_backend.CacheBackend[cache_backend.StringKey, string]
	lazyUpdateSF singleflight.Group
	closeOnce    sync.Once
	closeNotify  chan struct{}
	updatedKey   atomic.Uint64
}

func Init(bp *coremain.BP, args any) (any, error) {
	c, err := NewPtrRedisCache(args.(*Args), bp.Tag(), bp.L())
	if err != nil {
		return nil, err
	}

	tagNameMapMu.Lock()
	TagNameMap[bp.Tag()] = c
	tagNameMapMu.Unlock()
	return c, nil
}

func NewPtrRedisCache(args *Args, tag string, logger *zap.Logger) (*ReverseLookupRedisCache, error) {
	args.init()

	if logger == nil {
		logger = zap.NewNop()
	}

	backend, err := redis_cache_backend.NewRedisCache[cache_backend.StringKey, string](args.Url)
	if err != nil {
		return nil, fmt.Errorf("failed to init redis cache, %w", err)
	}
	p := &ReverseLookupRedisCache{
		args:        args,
		logger:      logger,
		backend:     backend,
		closeNotify: make(chan struct{}),
	}

	return p, nil
}

func (c *ReverseLookupRedisCache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	question := q.Question[0]
	qtype := question.Qtype
	if qtype == dns.TypePTR {
		r, _ := c.QueryDns(q)
		if r != nil {
			qCtx.SetResponse(r)
			return nil
		}
	}

	err := next.ExecNext(ctx, qCtx)

	if !c.args.ReadOnly && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		if r := qCtx.R(); r != nil {
			c.StoreDns(q, r)
		}
	}

	return err
}
