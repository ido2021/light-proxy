package common

import (
	"context"
	"net"
)

var adaptors = map[Protocol]Adaptor{}

type DialOut func(ctx context.Context, network, addr string) (net.Conn, error)

type Adaptor interface {
	HandleConn(ctx context.Context, conn net.Conn, router *Router)
}

func RegisterAdaptors(protocol Protocol, adaptor Adaptor) {
	adaptors[protocol] = adaptor
}

func GetAdaptor(protocol Protocol) Adaptor {
	return adaptors[protocol]
}
