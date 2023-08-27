package outbound

import (
	"context"
	"errors"
	"github.com/rs/dnscache"
	"math/rand"
	"net"
	"net/netip"
	"time"
)

type WrapperOutAdaptor struct {
	OutAdaptor
	resolver *dnscache.Resolver
	closed   chan struct{}
}

func NewWrapperOutAdaptor(outAdaptor OutAdaptor) *WrapperOutAdaptor {
	cacheOutAdaptor := &WrapperOutAdaptor{
		OutAdaptor: outAdaptor,
		closed:     make(chan struct{}, 1),
	}
	cacheOutAdaptor.resolver = &dnscache.Resolver{
		Resolver: cacheOutAdaptor,
	}
	go func() {
		t := time.NewTicker(30 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				cacheOutAdaptor.resolver.Refresh(true)
			case <-cacheOutAdaptor.closed:
				break
			}
		}
	}()
	return cacheOutAdaptor
}

func (wrapper *WrapperOutAdaptor) LookupAddr(ctx context.Context, addr string) (names []string, err error) {
	return nil, nil
}

func (wrapper *WrapperOutAdaptor) Resolve(ctx context.Context, host string) (net.IP, error) {
	addrs, err := wrapper.resolver.LookupHost(ctx, host)
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

func (wrapper *WrapperOutAdaptor) Close() error {
	wrapper.closed <- struct{}{}
	return wrapper.OutAdaptor.Close()
}
