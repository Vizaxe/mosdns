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
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

var (
	testArgs = &Args{
		Url:          "redis://127.0.0.1:6379/1",
		LazyCacheTTL: 86400,
		Separator:    ":",
		Prefix:       "test_prefix",
		StoreOnly:    false,
	}
	testCache, _ = NewRedisCache(testArgs, "test", nil)
)

// newTestQuery 构造一个测试用的 DNS 查询和响应。
func newTestQuery(t *testing.T) (*dns.Msg, *dns.Msg) {
	t.Helper()
	q := &dns.Msg{}
	q.Question = []dns.Question{{
		Name:   "test.xx.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	addr, _ := netip.ParseAddr("127.0.0.1")
	r := &dns.Msg{}
	r.SetReply(q)
	r.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Question[0].Name,
			Rrtype: q.Question[0].Qtype,
			Class:  q.Question[0].Qclass,
			Ttl:    600,
		},
		A: addr.AsSlice(),
	}}
	return q, r
}

// Test_StoreAndGet 验证写入后能正确读回，且 DNS 消息内容一致。
func Test_StoreAndGet(t *testing.T) {
	q, r := newTestQuery(t)
	key := getMsgKey(q, testArgs.Separator, testArgs.Prefix)

	// 先清理可能残留的旧数据
	_ = testCache.Clean()

	// 写入
	ok := testCache.saveRespToCache(key, r, testArgs.LazyCacheTTL, "")
	if !ok {
		t.Fatal("saveRespToCache returned false")
	}

	// 读取
	got, lazyHit := testCache.getRespFromCache(key, true, testArgs.LazyCacheTTL)
	if got == nil {
		t.Fatal("getRespFromCache returned nil")
	}

	// 验证响应内容
	if got.Rcode != r.Rcode {
		t.Errorf("Rcode mismatch: got %d, want %d", got.Rcode, r.Rcode)
	}
	if len(got.Answer) != len(r.Answer) {
		t.Fatalf("Answer count mismatch: got %d, want %d", len(got.Answer), len(r.Answer))
	}
	gotA, ok := got.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] is not *dns.A, got %T", got.Answer[0])
	}
	wantA := r.Answer[0].(*dns.A)
	if !gotA.A.Equal(wantA.A) {
		t.Errorf("A record mismatch: got %s, want %s", gotA.A, wantA.A)
	}

	t.Logf("round-trip OK: rcode=%d, answers=%d, lazyHit=%v", got.Rcode, len(got.Answer), lazyHit)
}

// Test_StoreAndGetNormalHit 验证非 lazy 模式下的缓存命中（未过期）。
func Test_StoreAndGetNormalHit(t *testing.T) {
	q, r := newTestQuery(t)
	key := getMsgKey(q, testArgs.Separator, testArgs.Prefix)

	// 写入（TTL 600 秒，不会立即过期）
	ok := testCache.saveRespToCache(key, r, 0, "")
	if !ok {
		t.Fatal("saveRespToCache returned false")
	}

	// 读取（不启用 lazy）
	got, lazyHit := testCache.getRespFromCache(key, false, 0)
	if got == nil {
		t.Fatal("getRespFromCache returned nil for non-lazy hit")
	}
	if lazyHit {
		t.Fatal("should not be lazy hit, response is not expired")
	}

	t.Logf("normal hit OK: rcode=%d, lazyHit=%v", got.Rcode, lazyHit)
}

// Test_Clean 验证 Clean 能删除缓存数据。
func Test_Clean(t *testing.T) {
	q, r := newTestQuery(t)
	key := getMsgKey(q, testArgs.Separator, testArgs.Prefix)

	// 写入
	testCache.saveRespToCache(key, r, testArgs.LazyCacheTTL, "")

	// 清理
	if err := testCache.Clean(); err != nil {
		t.Fatal("Clean failed:", err)
	}

	// 验证已删除
	got, _ := testCache.getRespFromCache(key, true, testArgs.LazyCacheTTL)
	if got != nil {
		t.Fatal("cache entry still exists after Clean")
	}

	t.Log("Clean OK")
}
