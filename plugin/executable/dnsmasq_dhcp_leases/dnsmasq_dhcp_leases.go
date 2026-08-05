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

package dnsmasq_dhcp_leases

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache/redis_cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/b0ch3nski/go-dnsmasq-utils/dnsmasq"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"os"
	"strings"
	"sync"
)

const PluginType = "dnsmasq_dhcp_leases"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*Leases)(nil)

type Args struct {
	File     string   `yaml:"file"`
	Suffixs  []string `yaml:"suffix"`
	CacheTag string   `yaml:"cache_tag"`
}

type Leases struct {
	args   *Args
	logger *zap.Logger
	file   string

	// mu 保护以下字段在 watch goroutine 和请求处理 goroutine 之间的并发访问
	mu         sync.RWMutex
	leases     []*dnsmasq.Lease
	ipv4Leases []*dnsmasq.Lease
	ipv6Leases []*dnsmasq.Lease
	leaseChan  chan []*dnsmasq.Lease
	matcher    domain.Matcher[*leasesGroup]

	// cache 用于缓存查询结果。仅支持 RedisCache（NewLeases 中类型断言）。
	// 使用具体类型以便通过 DeleteByQuery 增量清理缓存，避免 Clean 全量删除
	// 误伤同库共享同前缀的其他业务 key。
	cache *redis_cache.RedisCache

	// 以下字段仅由初始化流程与 watch goroutine 串行访问，
	// 记录上次同步到缓存的 hostname 与 PTR 名，用于增量删除。
	lastCacheFqdns    map[string]struct{}
	lastCachePtrFqdns map[string]struct{}

	// ctx 用于取消后台 goroutine，cancel 在 Close 时调用
	ctx    context.Context
	cancel context.CancelFunc
}

type leasesGroup struct {
	ipv4Leases []*dnsmasq.Lease
	ipv6Leases []*dnsmasq.Lease
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewLeases(bp, args.(*Args))
}

func NewLeases(bp *coremain.BP, args *Args) (*Leases, error) {
	if _, err := os.Stat(args.File); err != nil {
		return nil, fmt.Errorf("dnsmasq lease file %s: %w", args.File, err)
	}

	l := &Leases{
		args:      args,
		logger:    bp.L(),
		file:      args.File,
		leaseChan: make(chan []*dnsmasq.Lease),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())

	if len(strings.TrimSpace(args.CacheTag)) > 0 {
		redisCache, ok := bp.M().GetPlugin(args.CacheTag).(*redis_cache.RedisCache)
		if !ok {
			return nil, fmt.Errorf("%s is not a RedisCache plugin", args.CacheTag)
		}
		l.cache = redisCache
	}

	// 启动时立即读取一次文件，不依赖 inotify 事件
	f, err := os.Open(args.File)
	if err != nil {
		return nil, fmt.Errorf("failed to open dnsmasq lease file %s: %w", args.File, err)
	}
	initialLeases, err := dnsmasq.ReadLeases(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read dnsmasq lease file %s: %w", args.File, err)
	}
	l.leases = initialLeases
	ipMap := l.buildMatchers()
	// 初始化时同步一次缓存（锁外执行，Redis IO 不阻塞初始化）
	l.syncCache(ipMap)

	// 后台监听文件变更，使用可取消 context 以便 Close 时能终止 goroutine
	go dnsmasq.WatchLeases(l.ctx, l.file, l.leaseChan)
	go l.watch(l.ctx)
	return l, nil
}

func (l *Leases) watch(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case leaseBatch, ok := <-l.leaseChan:
			if !ok {
				return
			}
			l.mu.Lock()
			l.leases = leaseBatch
			ipMap := l.buildMatchers()
			l.mu.Unlock()
			// 缓存同步（Redis 网络 IO）放在锁外，
			// 避免文件变更时长时间阻塞查询路径的读锁。
			l.syncCache(ipMap)
		}
	}
}

// buildMatchers 基于当前 l.leases 构建内存匹配结构，返回 ipMap 供缓存同步使用。
// 必须在持有 l.mu（写锁）时调用。
func (l *Leases) buildMatchers() map[string]*leasesGroup {
	leases := l.leases
	ipMap := make(map[string]*leasesGroup)
	//if l.cache != nil {
	//	l.cache.StorePtrKeyPair(hostname, ipAddr.String(), -1)
	//}
	l.ipv4Leases = make([]*dnsmasq.Lease, 0)
	l.ipv6Leases = make([]*dnsmasq.Lease, 0)
	for _, lease := range leases {
		hostname := lease.Hostname
		ipAddr := lease.IPAddr
		//expires := lease.Expires
		if !ipAddr.IsValid() {
			continue
		}
		if hostname == "*" {
			continue
		}
		key := hostname + "."
		ips := ipMap[key]
		if ips == nil {
			ips = &leasesGroup{
				ipv4Leases: make([]*dnsmasq.Lease, 0),
				ipv6Leases: make([]*dnsmasq.Lease, 0),
			}
			ipMap[key] = ips
			for i2 := range l.args.Suffixs {
				suffix := l.args.Suffixs[i2]
				ipMap[key+suffix+"."] = ips
			}
		}

		if ipAddr.Is4() {
			ips.ipv4Leases = append(ips.ipv4Leases, lease)
			l.ipv4Leases = append(l.ipv4Leases, lease)
		} else if ipAddr.Is6() {
			ips.ipv6Leases = append(ips.ipv6Leases, lease)
			l.ipv6Leases = append(l.ipv6Leases, lease)
		}
	}
	m := domain.NewMixMatcher[*leasesGroup]()
	m.SetDefaultMatcher(domain.MatcherFull)
	for key := range ipMap {
		value := ipMap[key]
		m.Add(key, value)
	}
	l.matcher = m
	return ipMap
}

// syncCache 基于 ipMap 与上次同步记录做增量缓存同步（Redis 网络 IO）。
// 必须在锁外调用，避免阻塞查询路径。
func (l *Leases) syncCache(ipMap map[string]*leasesGroup) {
	if l.cache == nil {
		return
	}

	// 正向记录（hostname -> A/AAAA）
	newFqdns := make(map[string]struct{}, len(ipMap))
	for fqdn := range ipMap {
		newFqdns[fqdn] = struct{}{}
	}
	// 删除已消失的 hostname 缓存，避免误删本库其他业务 key（不再全量 Clean）。
	for fqdn := range l.lastCacheFqdns {
		if _, ok := newFqdns[fqdn]; !ok {
			l.deleteCache(fqdn, dns.TypeA)
			l.deleteCache(fqdn, dns.TypeAAAA)
		}
	}
	// 写入当前所有 hostname（幂等覆盖）。
	for fqdn := range ipMap {
		l.saveCache(fqdn, dns.TypeA)
		l.saveCache(fqdn, dns.TypeAAAA)
	}
	l.lastCacheFqdns = newFqdns

	// 反向记录（IP -> PTR）。
	newPtrFqdns := make(map[string]struct{})
	for _, g := range ipMap {
		for _, l4 := range g.ipv4Leases {
			if f := dnsutils.Ip2PtrFqdn(l4.IPAddr); len(f) > 0 {
				newPtrFqdns[f] = struct{}{}
			}
		}
		for _, l6 := range g.ipv6Leases {
			if f := dnsutils.Ip2PtrFqdn(l6.IPAddr); len(f) > 0 {
				newPtrFqdns[f] = struct{}{}
			}
		}
	}
	// 删除已消失的 PTR 缓存。
	for fqdn := range l.lastCachePtrFqdns {
		if _, ok := newPtrFqdns[fqdn]; !ok {
			l.deleteCache(fqdn, dns.TypePTR)
		}
	}
	// 写入当前所有 PTR（幂等覆盖）。
	for _, g := range ipMap {
		for _, l4 := range g.ipv4Leases {
			l.savePtr2Cache(l4.IPAddr)
		}
		for _, l6 := range g.ipv6Leases {
			l.savePtr2Cache(l6.IPAddr)
		}
	}
	l.lastCachePtrFqdns = newPtrFqdns
}

// deleteCache 按与 saveCache/savePtr2Cache 一致的 key 精确删除缓存条目。
func (l *Leases) deleteCache(fqdn string, qtype uint16) {
	if l.cache == nil {
		return
	}
	q := &dns.Msg{
		Question: []dns.Question{{Name: fqdn, Qclass: dns.ClassINET, Qtype: qtype}},
	}
	_ = l.cache.DeleteByQuery(q)
}

// Close 停止后台文件监听 goroutine，释放资源。
func (l *Leases) Close() error {
	if l.cancel != nil {
		l.cancel()
	}
	return nil
}

func (l *Leases) lookup(fqdn string) (ipv4, ipv6 []*dnsmasq.Lease) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ips, ok := l.matcher.Match(fqdn)
	if !ok {
		return nil, nil // no such host
	}
	return ips.ipv4Leases, ips.ipv6Leases
}

func (l *Leases) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if qCtx.R() == nil {
		if r := l.responsePtr(qCtx.Q()); r != nil {
			l.logger.Debug("dhcp ptr cache hit", qCtx.InfoField(), zap.Int("rcode", r.Rcode))
			qCtx.SetResponse(r)
		}
	}
	if qCtx.R() == nil {
		if r := l.responseQuery(qCtx.Q()); r != nil {
			l.logger.Debug("dhcp cache hit", qCtx.InfoField(), zap.Int("rcode", r.Rcode))
			qCtx.SetResponse(r)
		}
	}
	return nil
}
