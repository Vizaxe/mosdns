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

package redis_cache

import (
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

func (c *RedisCache) doLazyUpdate(msgKey string, qCtx *query_context.Context, next sequence.ChainWalker) {
	cache.LazyUpdate(
		c.asyncCtx,
		&c.lazyUpdateSF,
		c.logger,
		msgKey,
		qCtx,
		&next,
		func(r *dns.Msg) {
			c.saveRespToCache(msgKey, r, c.args.LazyCacheTTL, qCtx.GetBlackHoleTag())
			c.updatedKey.Add(1)
		},
	)
}

// saveRespToCache 将响应序列化为 protobuf wire format 并存入 Redis。
// 使用统一的 cache.CacheItem protobuf 定义，与 memory_cache dump 格式统一。
func (c *RedisCache) saveRespToCache(msgKey string, r *dns.Msg, lazyCacheTtl int, blackHoleTag string) bool {
	msgTtl, ok := cache.CalculateMsgTTL(r)
	if !ok {
		return false
	}

	var cacheTtl time.Duration
	if lazyCacheTtl == redis.KeepTTL {
		cacheTtl = redis.KeepTTL
	} else if lazyCacheTtl > 0 {
		cacheTtl = time.Duration(lazyCacheTtl) * time.Second
	} else {
		cacheTtl = msgTtl
	}

	wire, err := r.Pack()
	if err != nil {
		return false
	}

	item := &cache.CachedEntry{
		Msg:            wire,
		StoredTime:     time.Now().Unix(),
		ExpirationTime: time.Now().Add(msgTtl).Unix(),
		BlockHoleTag:   blackHoleTag,
	}
	data, err := item.Marshal()
	if err != nil {
		return false
	}
	c.backend.Store(cache_backend.StringKey(msgKey), string(data), cacheTtl)
	return true
}

func (c *RedisCache) getRespFromCache(msgKey string, lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool) {
	v, _, ok := c.backend.Get(cache_backend.StringKey(msgKey))
	if !ok {
		return nil, false
	}

	item := &cache.CachedEntry{}
	if err := item.Unmarshal([]byte(v)); err != nil {
		return nil, false
	}
	if len(item.Msg) == 0 {
		return nil, false
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(item.Msg); err != nil {
		return nil, false
	}

	cacheItem := &cache.Item{
		Resp:           resp,
		StoredTime:     time.Unix(item.StoredTime, 0),
		ExpirationTime: time.Unix(item.ExpirationTime, 0),
		BlockHoleTag:   item.BlockHoleTag,
	}
	return cache.PrepareCachedResponse(cacheItem, lazyCacheEnabled, lazyTtl)
}
