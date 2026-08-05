package dnsmasq_dhcp_leases

import (
	"github.com/IrineSistiana/mosdns/v5/pkg/dnsutils"
	"github.com/miekg/dns"
	"net/netip"
	"strings"
	"time"
)

func setDefaultVal(m *dns.Msg) *dns.Msg {
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

func (l *Leases) saveCache(fqdn string, qtype uint16) {
	if l.cache == nil {
		return
	}
	questions := make([]dns.Question, 0)
	questions = append(questions, dns.Question{
		Name:   fqdn,
		Qclass: dns.ClassINET,
		Qtype:  qtype,
	})
	q := &dns.Msg{
		Question: questions,
	}
	r := l.responseQuery(q)
	if r != nil && len(r.Answer) > 0 {
		l.cache.StoreDns(q, r)
	}
}

func (l *Leases) savePtr2Cache(addr netip.Addr) {
	if l.cache == nil {
		return
	}
	fqdn := dnsutils.Ip2PtrFqdn(addr)
	if len(strings.TrimSpace(fqdn)) > 0 {
		questions := make([]dns.Question, 0)
		questions = append(questions, dns.Question{
			Name:   fqdn,
			Qclass: dns.ClassINET,
			Qtype:  dns.TypePTR,
		})
		q := &dns.Msg{
			Question: questions,
		}

		r := l.responsePtr(q)
		if r != nil && len(r.Answer) > 0 {
			l.cache.StoreDns(q, r)
		}
	}
}

func (l *Leases) responsePtr(m *dns.Msg) *dns.Msg {
	if len(m.Question) != 1 {
		return nil
	}
	q := m.Question[0]
	typ := q.Qtype
	qcl := q.Qclass
	fqdn := q.Name
	if q.Qclass != dns.ClassINET || typ != dns.TypePTR {
		return nil
	}

	addr, _ := dnsutils.ParsePTRQName(fqdn)
	if !addr.IsValid() {
		return nil
	}
	var name string
	var ttl time.Duration
	l.mu.RLock()
	if addr.Is4() && len(l.ipv4Leases) > 0 {
		for i := range l.ipv4Leases {
			lease := l.ipv4Leases[i]
			ipAddr := lease.IPAddr
			if ipAddr.Compare(addr) == 0 {
				ttlDuration := lease.Expires.Sub(time.Now())
				if ttlDuration < 0 {
					ttlDuration = 0
				}
				name = lease.Hostname
				ttl = ttlDuration
				break
			}
		}
	} else if addr.Is6() && len(l.ipv6Leases) > 0 {
		for i := range l.ipv6Leases {
			lease := l.ipv6Leases[i]
			ipAddr := lease.IPAddr
			if ipAddr.Compare(addr) == 0 {
				ttlDuration := lease.Expires.Sub(time.Now())
				if ttlDuration < 0 {
					ttlDuration = 0
				}
				name = lease.Hostname
				ttl = ttlDuration
				break
			}
		}
	}
	l.mu.RUnlock()
	if len(name) > 0 {
		r := new(dns.Msg)
		setDefaultVal(r)
		r.SetReply(m)
		r.Answer = append(r.Answer, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: typ,
				Class:  qcl,
				Ttl:    uint32(ttl.Seconds()),
			},
			Ptr: name + ".",
		})
		r.Authoritative = true
		return r
	}
	return nil
}

func (l *Leases) responseQuery(m *dns.Msg) *dns.Msg {
	if len(m.Question) != 1 {
		return nil
	}
	q := m.Question[0]
	typ := q.Qtype
	fqdn := q.Name
	if q.Qclass != dns.ClassINET || (typ != dns.TypeA && typ != dns.TypeAAAA) {
		return nil
	}

	ipv4, ipv6 := l.lookup(fqdn)
	if len(ipv4)+len(ipv6) == 0 {
		return nil // no such host
	}

	now := time.Now()
	r := new(dns.Msg)
	setDefaultVal(r)
	r.SetReply(m)
	switch {
	case typ == dns.TypeA && len(ipv4) > 0:
		for _, lease := range ipv4 {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(lease.Expires.Sub(now).Seconds()),
				},
				A: lease.IPAddr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
	case typ == dns.TypeAAAA && len(ipv6) > 0:
		for _, lease := range ipv6 {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   fqdn,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(lease.Expires.Sub(now).Seconds()),
				},
				AAAA: lease.IPAddr.AsSlice(),
			}
			r.Answer = append(r.Answer, rr)
		}
	}

	// Append fake SOA record for empty reply.
	if len(r.Answer) == 0 {
		r.Ns = []dns.RR{dnsutils.FakeSOA(fqdn)}
	} else {
		r.Authoritative = true
	}
	return r
}
