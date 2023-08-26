package inbound

import (
	"encoding/json"
	"github.com/ido2021/light-proxy/route"
)

type Protocol string

const (
	HTTP   Protocol = "http"
	SOCKS4 Protocol = "socks4"
	SOCKS5 Protocol = "socks5"
	MIXED  Protocol = "mixed"
)

type InAdaptor interface {
	Start(router *route.Router) error
	Stop() error
}

type Factory func(config json.RawMessage) (InAdaptor, error)

var inAdaptorFactories = map[Protocol]Factory{}

func RegisterInAdaptorFactory(protocol Protocol, factory Factory) {
	inAdaptorFactories[protocol] = factory
}

func GetInAdaptorFactory(protocol Protocol) Factory {
	return inAdaptorFactories[protocol]
}
