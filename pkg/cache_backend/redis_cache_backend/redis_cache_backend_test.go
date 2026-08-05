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
	"fmt"
	"testing"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/redis/go-redis/v9"
)

var _ cache_backend.CacheBackend[cache_backend.StringKey, string] = (*RedisCache[cache_backend.StringKey, string])(nil)

//func BenchmarkUnmarshalDNS(b *testing.B) {
//	rawBytes := `{"Resp":{"Id":6733,"Response":true,"Opcode":0,"Authoritative":false,"Truncated":false,"RecursionDesired":true,"RecursionAvailable":true,"Zero":false,"AuthenticatedData":false,"CheckingDisabled":false,"Rcode":0,"Question":[{"Name":"www.qq.com.","Qtype":1,"Qclass":1}],"Answer":[{"Hdr":{"Name":"www.qq.com.","Rrtype":5,"Class":1,"Ttl":300,"Rdlength":36},"Target":"ins-r23tsuuf.ias.tencent-cloud.net."},{"Hdr":{"Name":"ins-r23tsuuf.ias.tencent-cloud.net.","Rrtype":1,"Class":1,"Ttl":300,"Rdlength":4},"A":"61.241.54.232"},{"Hdr":{"Name":"ins-r23tsuuf.ias.tencent-cloud.net.","Rrtype":1,"Class":1,"Ttl":300,"Rdlength":4},"A":"61.241.54.211"}],"Ns":[],"Extra":[]},"StoredTime":"2024-08-09T09:28:35.365373551+08:00","ExpirationTime":"2024-08-09T09:33:35.365373551+08:00"}`
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		unmarshalDNS([]byte(rawBytes))
//	}
//}

func TestRedisCache_Get(t *testing.T) {
	url := "redis://127.0.0.1:6379/6"
	c, err := NewRedisCache(url)
	if err != nil {
		t.Fatal(fmt.Errorf("invalid redis url, %w", err))
	}
	// 先写入再读取，确保测试自洽
	c.Store("test_query_cache:A:IN:qq.com.", "test_value", time.Minute*2)
	v, d, ok := c.Get("test_query_cache:A:IN:qq.com.")
	if !ok {
		t.Fatal(fmt.Errorf("get failed"))
	}
	fmt.Printf("%v - > %v", v, d)
}

func TestRedisCache_Store(t *testing.T) {
	url := "redis://127.0.0.1:6379/6"
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(fmt.Errorf("invalid redis url, %w", err))
	}
	opt.MaxRetries = -1
	c, err := NewRedisCache(url)
	if err != nil {
		t.Fatal(fmt.Errorf("invalid redis url, %w", err))
	}
	c.Store("test_query_cache:A:IN:qq.com.", "test", time.Minute*2)
}
