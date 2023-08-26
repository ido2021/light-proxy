package socks

import (
	"github.com/ido2021/light-proxy/adaptor/inbound"
)

const Socks4Version = 0x04

func init() {
	inbound.RegisterInAdaptorFactory(inbound.SOCKS4, NewSocks5Adaptor)
}
