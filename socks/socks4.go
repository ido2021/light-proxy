package socks

import "github.com/ido2021/mixedproxy/common"

const Socks4Version = 0x04

func init() {
	common.RegisterAdaptors(common.SOCKS4, &Socks5Adaptor{})
}
