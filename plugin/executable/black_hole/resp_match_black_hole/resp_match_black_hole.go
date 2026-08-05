package resp_ip_match_black_hole

import (
	"context"
	"fmt"
	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/domain"
	"github.com/IrineSistiana/mosdns/v5/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider"
	"github.com/IrineSistiana/mosdns/v5/plugin/data_provider/ip_set"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/black_hole"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"net"
	"net/netip"
)

const PluginType = "resp_match_black_hole"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.Executable = (*MatchBlackHole)(nil)

type Args struct {
	IPs     []string `yaml:"ips"`
	IPSets  []string `yaml:"ip_sets"`
	IPFiles []string `yaml:"ip_files"`

	CNameExps       []string `yaml:"cname_exps"`
	CNameDomainSets []string `yaml:"cname_domain_sets"`
	CNameFiles      []string `yaml:"cname_files"`

	BlackHoleSet   string   `yaml:"black_hole_set"`
	BlackHoleIPs   []string `yaml:"black_hole_ips"`
	BlackHoleFiles []string `yaml:"black_hole_files"`
}

type MatchBlackHole struct {
	logger    *zap.Logger
	tag       string
	nm        []netlist.Matcher
	dm        []domain.Matcher[struct{}]
	ipv4      []netip.Addr
	ipv6      []netip.Addr
	blackHole *black_hole.BlackHole
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewMatchBlackHole(bp, args.(*Args))
}

func NewMatchBlackHole(bp *coremain.BP, args *Args) (*MatchBlackHole, error) {

	p := &MatchBlackHole{
		logger: bp.L(),
		tag:    bp.Tag(),
	}
	l := netlist.NewList()
	if err := ip_set.LoadFromIPsAndFiles(args.IPs, args.IPFiles, l); err != nil {
		return nil, err
	}
	l.Sort()
	if l.Len() > 0 {
		p.nm = append(p.nm, l)
	}
	for _, tag := range args.IPSets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.IPMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not an IPMatcherProvider", tag)
		}
		p.nm = append(p.nm, provider.GetIPMatcher())
	}

	m := domain.NewDomainMixMatcher()
	if err := loadExpsAndFiles(args.CNameExps, args.CNameFiles, m); err != nil {
		return nil, err
	}
	if m.Len() > 0 {
		p.dm = append(p.dm, m)
	}

	for _, tag := range args.CNameDomainSets {
		provider, _ := bp.M().GetPlugin(tag).(data_provider.DomainMatcherProvider)
		if provider == nil {
			return nil, fmt.Errorf("%s is not a DomainMatcherProvider", tag)
		}
		m := provider.GetDomainMatcher()
		p.dm = append(p.dm, m)
	}

	if len(args.BlackHoleSet) > 0 {
		bh, ok := bp.M().GetPlugin(args.BlackHoleSet).(*black_hole.BlackHole)
		if !ok {
			return nil, fmt.Errorf("%s is not a BlackHole plugin", args.BlackHoleSet)
		}
		p.blackHole = bh
	} else {
		blackHole, err := black_hole.NewBlackHole(bp.L(), bp.Tag()+"@black_hole", &black_hole.Args{
			Ips:   args.BlackHoleIPs,
			Files: args.BlackHoleFiles,
		})
		if err != nil {
			return nil, err
		}
		p.blackHole = blackHole
	}

	return p, nil

}

func (b *MatchBlackHole) Exec(ctx context.Context, qCtx *query_context.Context) error {
	if b.matchesCName(qCtx, b.dm) || b.matchesRespAddr(qCtx, b.nm) {
		or := qCtx.R()
		if r := b.blackHole.Response(qCtx.Q()); r != nil {
			b.logger.Debug("result change", qCtx.InfoField(),
				zap.Int("orig_rcode", origRcode(or)),
				zap.Int("new_rcode", r.Rcode))
			if or := qCtx.R(); or != nil {
				qCtx.SetBlackHoleOrigResp(or)
			}
			qCtx.SetBlackHoleTag(b.tag)
			qCtx.SetResponse(r)
		}
	}
	return nil
}

// origRcode 安全获取 response 的 Rcode，nil 时返回 -1。
func origRcode(r *dns.Msg) int {
	if r == nil {
		return -1
	}
	return r.Rcode
}

func (b *MatchBlackHole) matchesRespAddr(qCtx *query_context.Context, ms []netlist.Matcher) bool {
	for _, m := range ms {
		if matchRespAddr(qCtx, m) {
			return true
		}
	}
	return false
}

func matchRespAddr(qCtx *query_context.Context, m netlist.Matcher) bool {
	r := qCtx.R()
	if r == nil {
		return false
	}
	for _, rr := range r.Answer {
		var ip net.IP
		switch rr := rr.(type) {
		case *dns.A:
			ip = rr.A
		case *dns.AAAA:
			ip = rr.AAAA
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if ok && m.Match(addr) {
			return true
		}
	}
	return false
}

func (b *MatchBlackHole) matchesCName(qCtx *query_context.Context, ms []domain.Matcher[struct{}]) bool {
	for _, m := range ms {
		if matchCName(qCtx, m) {
			return true
		}
	}
	return false
}

func matchCName(qCtx *query_context.Context, m domain.Matcher[struct{}]) bool {
	r := qCtx.R()
	if r == nil {
		return false
	}
	for _, rr := range r.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			if _, ok := m.Match(cname.Target); ok {
				return true
			}
		}
	}
	return false
}
