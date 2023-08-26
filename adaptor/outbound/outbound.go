package outbound

import (
	"context"
	"encoding/json"
	"net"
)

const (
	Direct = "direct"
	Block  = "block"
	Proxy  = "proxy"
)

type DialOut func(ctx context.Context, network, addr string) (net.Conn, error)

type OutAdaptor interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	// Resolve can be provided to do custom name resolution.
	Resolve(ctx context.Context, name string) (net.IP, error)
}

type Factory func(config json.RawMessage) (OutAdaptor, error)

var outAdaptorFactories = map[string]Factory{}

func RegisterOutAdaptorFactory(protocol string, factory Factory) {
	outAdaptorFactories[protocol] = factory
}

func GetOutAdaptorFactory(protocol string) Factory {
	return outAdaptorFactories[protocol]
}

type DirectOutAdaptor struct {
}

func (d *DirectOutAdaptor) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (d *DirectOutAdaptor) Resolve(ctx context.Context, name string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return nil, err
	}
	return addr.IP, err
}

type BlockOutAdaptor struct {
}

func (b *BlockOutAdaptor) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	//TODO implement me
	panic("implement me")
}

func (b *BlockOutAdaptor) Resolve(ctx context.Context, name string) (net.IP, error) {
	//TODO implement me
	panic("implement me")
}
