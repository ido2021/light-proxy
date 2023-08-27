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

type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

type OutAdaptor interface {
	Dial(ctx context.Context, network, addr string) (net.Conn, error)
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
	Close() error
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

func (d *DirectOutAdaptor) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	return net.LookupHost(host)
}

func (d *DirectOutAdaptor) Close() error {
	return nil
}

func (d *DirectOutAdaptor) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

type BlockOutAdaptor struct {
}

func (b *BlockOutAdaptor) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	return nil, nil
}

func (b *BlockOutAdaptor) Close() error {
	return nil
}

func (b *BlockOutAdaptor) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, nil
}
