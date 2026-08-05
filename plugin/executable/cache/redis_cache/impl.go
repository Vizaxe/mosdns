package redis_cache

import (
	"fmt"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/pkg/cache_backend"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

func (c *RedisCache) Get(key cache_backend.StringKey) string {
	value, _, _ := c.backend.Get(key)
	return value
}

func (c *RedisCache) Store(key cache_backend.StringKey, value string, ttl time.Duration) {
	c.backend.Store(key, value, ttl)
}

func (c *RedisCache) QueryDns(q *dns.Msg) (*dns.Msg, bool) {
	key := getMsgKey(q, c.args.Separator, c.args.Prefix)
	return c.getRespFromCache(key, c.args.LazyCacheTTL > 0 || c.args.LazyCacheTTL == redis.KeepTTL, cache_backend.ExpiredMsgTtl)
}

func (c *RedisCache) StoreDns(q *dns.Msg, r *dns.Msg) {
	key := getMsgKey(q, c.args.Separator, c.args.Prefix)
	c.saveRespToCache(key, r, c.args.LazyCacheTTL, "")
}

// DeleteByQuery 生成与 QueryDns/StoreDns 完全相同的 key 并删除该缓存条目。
// 供 dnsmasq_dhcp_leases 等数据源插件在数据变化时精确清理缓存，
// 避免使用 Clean（prefix:* 全量删除）误伤同库共享同前缀的其他业务 key。
func (c *RedisCache) DeleteByQuery(q *dns.Msg) error {
	key := getMsgKey(q, c.args.Separator, c.args.Prefix)
	if len(key) == 0 {
		return nil
	}
	return c.backend.Delete(cache_backend.StringKey(key))
}

func (c *RedisCache) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeNotify)
	})
	return c.backend.Close()
}

func (c *RedisCache) Clean() error {
	if len(strings.TrimSpace(c.args.Prefix)) > 0 && len(strings.TrimSpace(c.args.Separator)) > 0 {
		return c.backend.Delete(cache_backend.StringKey(fmt.Sprintf("%s%s*", c.args.Prefix, c.args.Separator)))
	}
	return nil
}
