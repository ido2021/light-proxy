package common

import (
	"context"
	"net"
)

type Transport interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve can be provided to do custom name resolution.
	Resolve(ctx context.Context, name string) (net.IP, error)
}

type DirectTransport struct {
}

func (direct *DirectTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (direct *DirectTransport) Resolve(ctx context.Context, name string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return nil, err
	}
	return addr.IP, err
}

type BlockTransport struct {
}

func (b *BlockTransport) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	//TODO implement me
	panic("implement me")
}

func (b *BlockTransport) Resolve(ctx context.Context, name string) (net.IP, error) {
	//TODO implement me
	panic("implement me")
}
