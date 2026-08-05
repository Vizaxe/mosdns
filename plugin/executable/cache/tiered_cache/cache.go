package tiered_cache

import (
	"context"
	"fmt"
	"sync"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

const PluginType = "tiered_cache"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.RecursiveExecutable = (*TieredCache)(nil)

type Args struct {
	L1Tag string `yaml:"l1_tag"`
	L2Tag string `yaml:"l2_tag"`
}

type dnsCacher interface {
	QueryDns(q *dns.Msg) (*dns.Msg, bool)
	StoreDns(q *dns.Msg, r *dns.Msg)
}

type TieredCache struct {
	l1   dnsCacher
	l2   dnsCacher
	bp   *coremain.BP
	args *Args

	lazyUpdateSF singleflight.Group
	closeOnce    sync.Once
	closeNotify  chan struct{}

	// asyncCtx 用于异步更新 goroutine，Close 时取消以终止残余 goroutine。
	asyncCtx    context.Context
	asyncCancel context.CancelFunc
}

func Init(bp *coremain.BP, args any) (any, error) {
	a := args.(*Args)
	return NewTieredCache(bp, a)
}

func NewTieredCache(bp *coremain.BP, args *Args) (*TieredCache, error) {
	if len(args.L1Tag) == 0 {
		return nil, fmt.Errorf("l1_tag is required")
	}
	if len(args.L2Tag) == 0 {
		return nil, fmt.Errorf("l2_tag is required")
	}

	p1 := bp.M().GetPlugin(args.L1Tag)
	if p1 == nil {
		return nil, fmt.Errorf("l1 cache plugin [%s] not found", args.L1Tag)
	}
	l1, ok := p1.(dnsCacher)
	if !ok {
		return nil, fmt.Errorf("plugin [%s] does not implement cache interface", args.L1Tag)
	}

	p2 := bp.M().GetPlugin(args.L2Tag)
	if p2 == nil {
		return nil, fmt.Errorf("l2 cache plugin [%s] not found", args.L2Tag)
	}
	l2, ok := p2.(dnsCacher)
	if !ok {
		return nil, fmt.Errorf("plugin [%s] does not implement cache interface", args.L2Tag)
	}

	t := &TieredCache{
		l1:          l1,
		l2:          l2,
		bp:          bp,
		args:        args,
		closeNotify: make(chan struct{}),
	}
	t.asyncCtx, t.asyncCancel = context.WithCancel(context.Background())
	go func() {
		select {
		case <-t.closeNotify:
			t.asyncCancel()
		case <-t.asyncCtx.Done():
		}
	}()
	return t, nil
}

// getMsgKey 生成用于 singleflight 去重的 key。
func (t *TieredCache) getMsgKey(q *dns.Msg) string {
	return cache.MsgQuestionKey(q, ":", "")
}

func (t *TieredCache) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	if qCtx.GetBlackHoleTag() != "" {
		return next.ExecNext(ctx, qCtx)
	}

	q := qCtx.Q()
	qCtx.CacheQueried = true

	// try L1
	if r, lazyHit := t.l1.QueryDns(q); r != nil {
		r.Id = q.Id
		qCtx.SetResponse(r)
		qCtx.CacheHit = true
		qCtx.CacheName = t.bp.Tag() + " -> " + t.args.L1Tag
		if lazyHit {
			t.asyncUpdate(q, qCtx, next)
		}
		err := next.ExecNext(ctx, qCtx)
		if qCtx.GetBlackHoleTag() == "" {
			query_context.RecordCache(true)
		}
		return err
	}

	// try L2
	if r, lazyHit := t.l2.QueryDns(q); r != nil {
		r.Id = q.Id
		qCtx.SetResponse(r)
		t.l1.StoreDns(q, r)
		qCtx.CacheHit = true
		qCtx.CacheName = t.bp.Tag() + " -> " + t.args.L2Tag
		if lazyHit {
			t.asyncUpdate(q, qCtx, next)
		}
		err := next.ExecNext(ctx, qCtx)
		if qCtx.GetBlackHoleTag() == "" {
			query_context.RecordCache(true)
		}
		return err
	}

	err := next.ExecNext(ctx, qCtx)

	if err != nil {
		return err
	}

	if qCtx.GetBlackHoleTag() == "" {
		qCtx.CacheHit = false
		query_context.RecordCache(false)
		if qCtx.R() != nil {
			t.l1.StoreDns(q, qCtx.R())
			// L2 (Redis) 存储异步执行，避免慢 Redis 阻塞请求链。
			// 传入深拷贝避免异步 goroutine 与主 goroutine 竞争。
			// StoreDns 内部有自己的 2 秒超时，无需额外 ctx。
			qCopy := q.Copy()
			rCopy := qCtx.R().Copy()
			go t.l2.StoreDns(qCopy, rCopy)
		}
	}

	return nil
}

// asyncUpdate 复用 cache.LazyUpdate 执行异步更新，与 redis_cache/memory_cache 保持一致。
// 使用 singleflight 去重，更新结果同时写入 L1 和 L2。
func (t *TieredCache) asyncUpdate(q *dns.Msg, qCtx *query_context.Context, next sequence.ChainWalker) {
	key := t.getMsgKey(q)
	if key == "" {
		return
	}

	cache.LazyUpdate(
		t.asyncCtx,
		&t.lazyUpdateSF,
		t.bp.L(),
		key,
		qCtx,
		&next,
		func(r *dns.Msg) {
			qCopy := q.Copy()
			t.l1.StoreDns(qCopy, r)
			t.l2.StoreDns(qCopy, r)
		},
	)
}

// Close 通知异步更新 goroutine 停止，释放资源。
func (t *TieredCache) Close() error {
	t.closeOnce.Do(func() {
		close(t.closeNotify)
	})
	return nil
}
