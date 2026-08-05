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

package memory_cache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend/memory_cache_backend"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/go-chi/chi/v5"
	"github.com/klauspost/compress/gzip"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	PluginType = "cache"
)

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetupCache)
}

const (
	expiredMsgTtl = 5

	minimumChangesToDump   = 1024
	dumpHeader             = "mosdns_cache_v2"
	dumpBlockSize          = 128
	dumpMaximumBlockLength = 1 << 20 // 1M block. 8kb pre entry. Should be enough.
)

var _ sequence.RecursiveExecutable = (*MemoryCache)(nil)

type Args struct {
	Size         int    `yaml:"size"`
	LazyCacheTTL int    `yaml:"lazy_cache_ttl"`
	DumpFile     string `yaml:"dump_file"`
	DumpInterval int    `yaml:"dump_interval"`
	EdnsKey      *bool  `yaml:"edns_key"`
}

func (a *Args) init() {
	utils.SetDefaultUnsignNum(&a.Size, 1024)
	utils.SetDefaultUnsignNum(&a.DumpInterval, 600)
	if a.EdnsKey == nil {
		v := true
		a.EdnsKey = &v
	}
}

type MemoryCache struct {
	args *Args
	tag  string

	logger       *zap.Logger
	backend      *memory_cache_backend.MemoryCache[key, *cache.Item]
	lazyUpdateSF singleflight.Group
	closeOnce    sync.Once
	closeNotify  chan struct{}
	updatedKey   atomic.Uint64

	// asyncCtx 用于异步 lazy update goroutine，Close 时取消以终止残余 goroutine。
	asyncCtx    context.Context
	asyncCancel context.CancelFunc

	queryTotal   prometheus.Counter
	hitTotal     prometheus.Counter
	lazyHitTotal prometheus.Counter
	size         prometheus.GaugeFunc
}

func Init(bp *coremain.BP, args any) (any, error) {
	c := NewMemoryCache(args.(*Args), Opts{
		Logger:     bp.L(),
		MetricsTag: bp.Tag(),
		Tag:        bp.Tag(),
	})

	if err := c.RegMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		return nil, fmt.Errorf("failed to register metrics, %w", err)
	}
	bp.RegAPI(c.Api())
	return c, nil
}

// QuickSetup format: [size]
// default is 1024. If size is < 1024, 1024 will be used.
func quickSetupCache(bq sequence.BQ, s string) (any, error) {
	size := 0
	if len(s) > 0 {
		i, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid size, %w", err)
		}
		size = i
	}
	// Don't register metrics in quick setup.
	return NewMemoryCache(&Args{Size: size}, Opts{Logger: bq.L(), Tag: PluginType}), nil
}

type Opts struct {
	Logger     *zap.Logger
	MetricsTag string
	Tag        string
}

func NewMemoryCache(args *Args, opts Opts) *MemoryCache {
	args.init()

	logger := opts.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	backend := memory_cache_backend.NewMemoryCache[key, *cache.Item](memory_cache_backend.MemoryCacheOpts{Size: args.Size})
	lb := map[string]string{"tag": opts.MetricsTag}
	p := &MemoryCache{
		args:        args,
		tag:         opts.Tag,
		logger:      logger,
		backend:     backend,
		closeNotify: make(chan struct{}),

		queryTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "query_total",
			Help:        "The total number of processed queries",
			ConstLabels: lb,
		}),
		hitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "hit_total",
			Help:        "The total number of queries that hit the cache",
			ConstLabels: lb,
		}),
		lazyHitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name:        "lazy_hit_total",
			Help:        "The total number of queries that hit the expired cache",
			ConstLabels: lb,
		}),
		size: prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name:        "size_current",
			Help:        "Current cache size in records",
			ConstLabels: lb,
		}, func() float64 {
			return float64(backend.Len())
		}),
	}

	p.asyncCtx, p.asyncCancel = context.WithCancel(context.Background())
	go func() {
		select {
		case <-p.closeNotify:
			p.asyncCancel()
		case <-p.asyncCtx.Done():
		}
	}()

	if err := p.loadDump(); err != nil {
		p.logger.Error("failed to load cache dump", zap.Error(err))
	}
	p.startDumpLoop()

	return p
}

func (c *MemoryCache) RegMetricsTo(r prometheus.Registerer) error {
	for _, collector := range [...]prometheus.Collector{c.queryTotal, c.hitTotal, c.lazyHitTotal, c.size} {
		if err := r.Register(collector); err != nil {
			return err
		}
	}
	return nil
}

func (c *MemoryCache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if qCtx.GetBlackHoleTag() != "" {
		return next.ExecNext(ctx, qCtx)
	}

	c.queryTotal.Inc()
	q := qCtx.Q()

	// 统一走 getKey，保证 edns_key 配置在 Exec 路径同样生效，
	// 否则 edns_key: false 时 Exec 仍生成含 EDNS 标志的 key，
	// 与 QueryDns/StoreDns 的 key 不一致，导致缓存失效。
	msgKey := c.getKey(q)
	if len(msgKey) == 0 { // skip cache
		return next.ExecNext(ctx, qCtx)
	}

	qCtx.CacheQueried = true
	cachedResp, lazyHit := getRespFromCache(msgKey, c.backend, c.args.LazyCacheTTL > 0, expiredMsgTtl)
	if lazyHit {
		c.lazyHitTotal.Inc()
		c.doLazyUpdate(msgKey, qCtx, next)
	}
	if cachedResp != nil { // cache hit
		c.hitTotal.Inc()
		cachedResp.Id = q.Id // change msg id
		qCtx.SetResponse(cachedResp)
		qCtx.CacheHit = true
		qCtx.CacheName = c.tag
	} else {
		qCtx.CacheHit = false
	}

	err := next.ExecNext(ctx, qCtx)

	if qCtx.GetBlackHoleTag() == "" {
		if cachedResp != nil {
			query_context.RecordCache(true)
		} else {
			query_context.RecordCache(false)
		}

		if r := qCtx.R(); r != nil && cachedResp != r { // pointer compare. r is not cachedResp
			saveRespToCache(msgKey, r, c.backend, c.args.LazyCacheTTL)
			c.updatedKey.Add(1)
		}
	}
	return err
}

// doLazyUpdate 异步执行 next 链并更新缓存。
// 使用结构体级别的 asyncCtx，避免每次调用都创建 context + 监控 goroutine 造成泄漏。
func (c *MemoryCache) doLazyUpdate(msgKey string, qCtx *query_context.Context, next sequence.ChainWalker) {
	cache.LazyUpdate(
		c.asyncCtx,
		&c.lazyUpdateSF,
		c.logger,
		msgKey,
		qCtx,
		&next,
		func(r *dns.Msg) {
			saveRespToCache(msgKey, r, c.backend, c.args.LazyCacheTTL)
			c.updatedKey.Add(1)
		},
	)
}

func (c *MemoryCache) loadDump() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}
	if _, err := os.Stat(c.args.DumpFile); err != nil {
		return fmt.Errorf("cache dump file %s: %w", c.args.DumpFile, err)
	}
	f, err := os.Open(c.args.DumpFile)
	if err != nil {
		return fmt.Errorf("failed to open cache dump %s: %w", c.args.DumpFile, err)
	}
	defer f.Close()
	en, err := c.readDump(f)
	if err != nil {
		return fmt.Errorf("failed to read cache dump %s: %w", c.args.DumpFile, err)
	}
	c.logger.Info("cache dump loaded", zap.Int("entries", en))
	return nil
}

// startDumpLoop starts a dump loop in another goroutine. It does not block.
func (c *MemoryCache) startDumpLoop() {
	if len(c.args.DumpFile) == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Duration(c.args.DumpInterval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Check if we have enough changes to dump.
				keyUpdated := c.updatedKey.Swap(0)
				if keyUpdated < minimumChangesToDump { // Nop.
					c.updatedKey.Add(keyUpdated)
					continue
				}

				if err := c.dumpCache(); err != nil {
					c.logger.Error("dump cache", zap.Error(err))
				}
			case <-c.closeNotify:
				return
			}
		}
	}()
}

func (c *MemoryCache) dumpCache() error {
	if len(c.args.DumpFile) == 0 {
		return nil
	}

	f, err := os.Create(c.args.DumpFile)
	if err != nil {
		return err
	}
	defer f.Close()

	en, err := c.writeDump(f)
	if err != nil {
		return fmt.Errorf("failed to write dump, %w", err)
	}
	c.logger.Info("cache dumped", zap.Int("entries", en))
	return nil
}

func (c *MemoryCache) Api() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/flush", func(w http.ResponseWriter, req *http.Request) {
		c.backend.Flush()
	})
	r.Get("/dump", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "application/octet-stream")
		_, err := c.writeDump(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	r.Post("/load_dump", func(w http.ResponseWriter, req *http.Request) {
		if _, err := c.readDump(req.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func (c *MemoryCache) writeDump(w io.Writer) (int, error) {
	en := 0

	gw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	gw.Name = dumpHeader
	gwClosed := false
	defer func() {
		if !gwClosed {
			_ = gw.Close()
		}
	}()

	block := new(cache.CacheDumpBlock)
	writeBlock := func() error {
		b, err := block.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal protobuf, %w", err)
		}

		l := make([]byte, 8)
		binary.BigEndian.PutUint64(l, uint64(len(b)))
		_, err = gw.Write(l)
		if err != nil {
			return fmt.Errorf("failed to write header, %w", err)
		}
		_, err = gw.Write(b)
		if err != nil {
			return fmt.Errorf("failed to write data, %w", err)
		}

		en += len(block.GetEntries())
		block.Reset()
		return nil
	}

	now := time.Now()
	rangeFunc := func(k key, v *cache.Item, cacheExpirationTime time.Time) error {
		if cacheExpirationTime.Before(now) {
			return nil
		}
		msg, err := v.Resp.Pack()
		if err != nil {
			return fmt.Errorf("failed to pack msg, %w", err)
		}
		e := &cache.CachedEntry{
			Key:                 []byte(k),
			CacheExpirationTime: cacheExpirationTime.Unix(),
			ExpirationTime:      v.ExpirationTime.Unix(),
			Msg:                 msg,
		}
		block.Entries = append(block.Entries, e)

		// Block is big enough for a write operation.
		if len(block.Entries) >= dumpBlockSize {
			return writeBlock()
		}
		return nil
	}
	if err := c.backend.Range(rangeFunc); err != nil {
		return en, err
	}

	if len(block.GetEntries()) > 0 {
		if err := writeBlock(); err != nil {
			return en, err
		}
	}
	gwClosed = true
	return en, gw.Close()
}

// readDump reads dumped data from r. It returns the number of bytes read,
// number of entries read and any error encountered.
func (c *MemoryCache) readDump(r io.Reader) (int, error) {
	en := 0
	gr, err := gzip.NewReader(r)
	if err != nil {
		return en, fmt.Errorf("failed to read gzip header, %w", err)
	}
	if gr.Name != dumpHeader {
		return en, fmt.Errorf("invalid or old cache dump, header is %s, want %s", gr.Name, dumpHeader)
	}
	grClosed := false
	defer func() {
		if !grClosed {
			_ = gr.Close()
		}
	}()

	var errReadHeaderEOF = errors.New("")
	readBlock := func() error {
		h := pool.GetBuf(8)
		defer pool.ReleaseBuf(h)
		_, err := io.ReadFull(gr, *h)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return errReadHeaderEOF
			}
			return fmt.Errorf("failed to read block header, %w", err)
		}
		u := binary.BigEndian.Uint64(*h)
		if u > dumpMaximumBlockLength {
			return fmt.Errorf("invalid header, block length is big, %d", u)
		}

		b := pool.GetBuf(int(u))
		defer pool.ReleaseBuf(b)
		_, err = io.ReadFull(gr, *b)
		if err != nil {
			return fmt.Errorf("failed to read block data, %w", err)
		}

		block := new(cache.CacheDumpBlock)
		if err := block.Unmarshal(*b); err != nil {
			return fmt.Errorf("failed to decode block data, %w", err)
		}

		en += len(block.GetEntries())
		for _, entry := range block.GetEntries() {
			cacheExpTime := time.Unix(entry.CacheExpirationTime, 0)
			msgExpTime := time.Unix(entry.ExpirationTime, 0)
			storedTime := time.Unix(entry.StoredTime, 0)
			resp := new(dns.Msg)
			if err := resp.Unpack(entry.Msg); err != nil {
				return fmt.Errorf("failed to decode dns msg, %w", err)
			}

			i := &cache.Item{
				Resp:           resp,
				StoredTime:     storedTime,
				ExpirationTime: msgExpTime,
			}
			c.backend.Store(key(entry.Key), i, time.Now().Sub(cacheExpTime))
		}
		return nil
	}

	for {
		err = readBlock()
		if err != nil {
			if err == errReadHeaderEOF {
				err = nil // This is expected if there is no block to read.
			}
			break
		}
	}

	if err != nil {
		return en, err
	}
	grClosed = true
	return en, gr.Close()
}
