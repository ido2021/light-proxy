package route

import (
	"errors"
	"github.com/ido2021/light-proxy/adaptor/outbound"
	"github.com/ido2021/light-proxy/common"
	"strings"
)

type Rule struct {
	domains        map[string]struct{}
	domainSuffixes []string
	domainPath     string
	outAdaptor     *outbound.WrapperOutAdaptor
}

func (r *Rule) Match(metadata *common.Metadata) bool {
	dn := metadata.DestAddr.FQDN
	_, exist := r.domains[dn]
	if exist {
		return true
	}
	for _, suffix := range r.domainSuffixes {
		if strings.HasSuffix(dn, suffix) {
			return true
		}
	}
	return false
}

type Router struct {
	rules []*Rule
	final *outbound.WrapperOutAdaptor
}

func NewRouter(route common.Route, outAdaptors map[string]*outbound.WrapperOutAdaptor) (*Router, error) {
	var rules []*Rule
	for _, ruleConfig := range route.Rules {
		outAdaptor, exist := outAdaptors[ruleConfig.Outbound]
		if exist {
			return nil, errors.New("未配置接出代理：" + ruleConfig.Outbound)
		}

		domains := map[string]struct{}{}
		for _, domain := range ruleConfig.Domain {
			domains[domain] = struct{}{}
		}

		rule := &Rule{
			domains:        domains,
			domainSuffixes: ruleConfig.DomainSuffix,
			outAdaptor:     outAdaptor,
		}
		rules = append(rules, rule)
	}

	final := route.Final
	if final == "" {
		final = outbound.Proxy
	}
	outAdaptor, exist := outAdaptors[final]
	if !exist {
		return nil, errors.New("未配置接出代理：" + route.Final)
	}

	return &Router{
		rules: rules,
		final: outAdaptor,
	}, nil
}

func (r *Router) Route(metadata *common.Metadata) *outbound.WrapperOutAdaptor {
	for _, rule := range r.rules {
		if rule.Match(metadata) {
			return rule.outAdaptor
		}
	}
	return r.final
}
