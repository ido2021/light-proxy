package light_proxy

import (
	"context"
	"errors"
	"github.com/ido2021/light-proxy/adaptor/outbound"
	"github.com/rs/dnscache"
	"math/rand"
	"net"
	"net/netip"
)

type DNSCacheOutAdaptor struct {
	outbound.OutAdaptor
	resolver *dnscache.Resolver
}

func NewDNSCacheOutAdaptor(outAdaptor outbound.OutAdaptor) outbound.OutAdaptor {
	cacheOutAdaptor := &DNSCacheOutAdaptor{
		OutAdaptor: outAdaptor,
	}
	cacheOutAdaptor.resolver = &dnscache.Resolver{
		Resolver: cacheOutAdaptor,
	}

	return cacheOutAdaptor
}

func (cache *DNSCacheOutAdaptor) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	return nil, nil
}

func (cache *DNSCacheOutAdaptor) Resolve(ctx context.Context, host string) (net.IP, error) {
	addrs, err := cache.resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + host)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	return addr.AsSlice(), nil
}
