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

package redis_cache_backend

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	backends   = make(map[string]*redisBackendRef)
	backendsMu sync.Mutex
)

type redisBackendRef struct {
	client *redis.Client
	refs   int
}

func getOrCreateClient(addr string) (*redisBackendRef, error) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	if ref, ok := backends[addr]; ok {
		ref.refs++
		return ref, nil
	}
	opt, err := redis.ParseURL(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid redis url, %w", err)
	}
	opt.MaxRetries = -1
	ref := &redisBackendRef{
		client: redis.NewClient(opt),
		refs:   1,
	}
	backends[addr] = ref
	return ref, nil
}

func releaseClient(addr string) {
	backendsMu.Lock()
	defer backendsMu.Unlock()
	if ref, ok := backends[addr]; ok {
		ref.refs--
		if ref.refs <= 0 {
			ref.client.Close()
			delete(backends, addr)
		}
	}
}

var nopLogger = zap.NewNop()

type RedisCache[K cache_backend.StringKey, V string] struct {
	addr string

	closed atomic.Bool

	client *redis.Client
}

func NewRedisCache[K cache_backend.StringKey, V string](addr string) (*RedisCache[K, V], error) {
	ref, err := getOrCreateClient(addr)
	if err != nil {
		return nil, err
	}
	return &RedisCache[K, V]{
		addr:   addr,
		client: ref.client,
	}, nil
}

func (c *RedisCache[K, V]) Close() error {
	if ok := c.closed.CompareAndSwap(false, true); !ok {
		return nil
	}
	releaseClient(c.addr)
	return nil
}

func (c *RedisCache[K, V]) Get(key K) (value V, expirationTime time.Time, ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	data, err := c.client.Get(ctx, string(key)).Result()
	if err != nil {
		if err != redis.Nil {
			nopLogger.Warn("redis get", zap.Error(err))
		}
		return V(data), time.Now(), false
	}
	// 过期时间由调用方从数据内容中解析（Item 内含 ExpirationTime），
	// 无需额外发起 TTL 请求，减少一次网络往返。
	return V(data), time.Now(), true
}

// Store stores this kv in cache. If expirationTime is before time.Now(),
// Store is an noop.
func (c *RedisCache[K, V]) Store(key K, msg V, cacheTtl time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	if err := c.client.Set(ctx, string(key), msg, cacheTtl).Err(); err != nil {
		nopLogger.Warn("redis set", zap.Error(err))
	}
}

// Len returns the current size of this cache.
func (c *RedisCache[K, V]) Len() int {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()
	i, err := c.client.DBSize(ctx).Result()
	if err != nil {
		nopLogger.Error("dbsize", zap.Error(err))
		return 0
	}
	return int(i)
}

func (c *RedisCache[K, V]) Range(f func(key K, value V, expirationTime time.Time) error) error {
	return nil
}

func (c *RedisCache[K, V]) Flush() {
}

func (c *RedisCache[K, V]) Delete(key K) error {
	keyStr := string(key)
	// 如果 key 包含 glob 字符，使用 SCAN 安全地批量删除
	if containsGlob(keyStr) {
		return c.deleteByScan(keyStr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	return c.client.Del(ctx, keyStr).Err()
}

// containsGlob 检查字符串是否包含 Redis KEYS 通配符。
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// deleteByScan 使用 SCAN + DEL 安全地删除匹配 pattern 的所有键，
// 避免 KEYS 命令对 Redis 的阻塞。
func (c *RedisCache[K, V]) deleteByScan(pattern string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	var cursor uint64
	var totalDeleted int
	for {
		keys, nextCursor, err := c.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("scan error: %w", err)
		}
		if len(keys) > 0 {
			if _, err := c.client.Del(ctx, keys...).Result(); err != nil {
				return fmt.Errorf("del error: %w", err)
			}
			totalDeleted += len(keys)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}
