package cache

import (
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"time"
)

func SetDefaultVal(m *dns.Msg) *dns.Msg {
	if m == nil {
		return nil
	}
	if m.Answer == nil {
		m.Answer = make([]dns.RR, 0)
	}
	if m.Ns == nil {
		m.Ns = make([]dns.RR, 0)
	}
	if m.Extra == nil {
		m.Extra = make([]dns.RR, 0)
	}
	return m
}

// CopyMsgNoOpt deep copies m and excludes OPT records.
func CopyMsgNoOpt(m *dns.Msg) *dns.Msg {
	return copyMsgNoOptWithTTL(m, 0, false)
}

// copyMsgNoOptWithTTL deep copies m, excludes OPT records, and adjusts TTL in one pass.
// If subtract is true, ttlDelta is subtracted from each RR's TTL.
// If subtract is false, all RRs' TTL is set to ttlDelta.
func copyMsgNoOptWithTTL(m *dns.Msg, ttlDelta uint32, subtract bool) *dns.Msg {
	if m == nil {
		return nil
	}

	adjustTTL := func(h *dns.RR_Header) {
		if subtract {
			if h.Ttl > ttlDelta {
				h.Ttl -= ttlDelta
			} else {
				h.Ttl = 1
			}
		} else {
			h.Ttl = ttlDelta
		}
	}

	m2 := new(dns.Msg)
	m2.MsgHdr = m.MsgHdr
	m2.Compress = m.Compress

	if len(m.Question) > 0 {
		m2.Question = make([]dns.Question, len(m.Question))
		copy(m2.Question, m.Question)
	}

	m2.Answer = make([]dns.RR, len(m.Answer))
	for i, r := range m.Answer {
		cp := dns.Copy(r)
		adjustTTL(cp.Header())
		m2.Answer[i] = cp
	}
	m2.Ns = make([]dns.RR, len(m.Ns))
	for i, r := range m.Ns {
		cp := dns.Copy(r)
		adjustTTL(cp.Header())
		m2.Ns[i] = cp
	}

	m2.Extra = make([]dns.RR, 0, len(m.Extra))
	for _, r := range m.Extra {
		if r.Header().Rrtype == dns.TypeOPT {
			continue
		}
		cp := dns.Copy(r)
		adjustTTL(cp.Header())
		m2.Extra = append(m2.Extra, cp)
	}
	return m2
}

func CalculateMsgTTL(r *dns.Msg) (msgTtl time.Duration, shouldCache bool) {
	if r.Truncated {
		return 0, false
	}

	switch r.Rcode {
	case dns.RcodeNameError:
		msgTtl = 30 * time.Second
	case dns.RcodeServerFailure:
		msgTtl = 5 * time.Second
	case dns.RcodeSuccess:
		minTTL := dnsutils.GetMinimalTTL(r)
		if len(r.Answer) == 0 {
			const maxEmptyAnswerTtl = 300
			msgTtl = time.Duration(min(minTTL, maxEmptyAnswerTtl)) * time.Second
		} else {
			msgTtl = time.Duration(minTTL) * time.Second
		}
	default:
		return 0, false
	}
	if msgTtl <= 0 {
		return 0, false
	}
	return msgTtl, true
}

// PrepareCachedResponse adjusts TTL based on elapsed time.
// Returns the response and whether it's a lazy (expired) hit.
func PrepareCachedResponse(item *Item, lazyCacheEnabled bool, lazyTtl int) (*dns.Msg, bool) {
	now := time.Now()

	if now.Before(item.ExpirationTime) {
		r := copyMsgNoOptWithTTL(item.Resp, uint32(now.Sub(item.StoredTime).Seconds()), true)
		return r, false
	}

	if lazyCacheEnabled {
		r := copyMsgNoOptWithTTL(item.Resp, uint32(lazyTtl), false)
		return r, true
	}

	return nil, false
}

func NewCacheItem(r *dns.Msg, msgTtl time.Duration, blackHoleTag string) *Item {
	now := time.Now()
	return &Item{
		Resp:           CopyMsgNoOpt(r),
		StoredTime:     now,
		ExpirationTime: now.Add(msgTtl),
		BlockHoleTag:   blackHoleTag,
	}
}
