package domain_map

import (
	"context"
	"fmt"
	"strings"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "domain_map"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
}

var _ sequence.RecursiveExecutable = (*DomainMap)(nil)

type Args struct {
	Mappings map[string]string `yaml:"mappings"`
}

type DomainMap struct {
	mappings map[string]string
}

func Init(bp *coremain.BP, args any) (any, error) {
	return NewDomainMap(args.(*Args))
}

func NewDomainMap(args *Args) (*DomainMap, error) {
	if len(args.Mappings) == 0 {
		return nil, fmt.Errorf("no mapping configured")
	}
	mappings := make(map[string]string, len(args.Mappings))
	for k, v := range args.Mappings {
		if len(k) == 0 || len(v) == 0 {
			return nil, fmt.Errorf("invalid mapping: %q -> %q", k, v)
		}
		mappings[strings.ToLower(dns.Fqdn(k))] = dns.Fqdn(v)
	}
	return &DomainMap{mappings: mappings}, nil
}

func (d *DomainMap) Exec(ctx context.Context, qCtx *query_context.Context, next sequence.ChainWalker) error {
	q := qCtx.Q()
	if len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET {
		return next.ExecNext(ctx, qCtx)
	}

	orgQName := q.Question[0].Name
	target, ok := d.mappings[strings.ToLower(orgQName)]
	if !ok {
		return next.ExecNext(ctx, qCtx)
	}

	q.Question[0].Name = target
	defer func() {
		q.Question[0].Name = orgQName
	}()

	err := next.ExecNext(ctx, qCtx)
	if r := qCtx.R(); r != nil {
		for i := range r.Question {
			if r.Question[i].Name == target {
				r.Question[i].Name = orgQName
			}
		}
		for _, rr := range r.Ns {
			rewriteOwner(rr, target, orgQName)
		}
		for _, rr := range r.Extra {
			rewriteOwner(rr, target, orgQName)
		}
		for _, rr := range r.Answer {
			if cname, ok := rr.(*dns.CNAME); ok && cname.Target == orgQName {
				continue
			}
			rewriteOwner(rr, target, orgQName)
		}
	}
	return err
}

func rewriteOwner(rr dns.RR, old, new string) {
	h := rr.Header()
	if strings.EqualFold(h.Name, old) {
		h.Name = new
	}
}
