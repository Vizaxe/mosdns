package memory_cache

import (
	"time"

	"github.com/IrineSistiana/mosdns/v5/plugin/executable/cache"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func (c *MemoryCache) Get(key key) *cache.Item {
	value, _, _ := c.backend.Get(key)
	return value
}

func (c *MemoryCache) Store(key key, value *cache.Item, ttl time.Duration) {
	c.backend.Store(key, value, ttl)
}

func (c *MemoryCache) getKey(q *dns.Msg) string {
	if q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return ""
	}
	if *c.args.EdnsKey {
		return getMsgKey(q) // 原逻辑，包含 EDNS 标志位
	}
	return cache.MsgQuestionKey(q, ":", "") // 仅使用问题定义
}

func (c *MemoryCache) QueryDns(q *dns.Msg) (*dns.Msg, bool) {
	key := c.getKey(q)
	return getRespFromCache(key, c.backend, c.args.LazyCacheTTL > 0, expiredMsgTtl)
}

func (c *MemoryCache) StoreDns(q *dns.Msg, r *dns.Msg) {
	key := c.getKey(q)
	saveRespToCache(key, r, c.backend, c.args.LazyCacheTTL)
}

func (c *MemoryCache) Close() error {
	if err := c.dumpCache(); err != nil {
		c.logger.Error("failed to dump cache", zap.Error(err))
	}
	c.closeOnce.Do(func() {
		close(c.closeNotify)
	})
	return c.backend.Close()
}

func (c *MemoryCache) Clean() error {
	return nil
}
