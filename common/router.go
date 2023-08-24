package common

type Router struct {
	proxyTransport  Transport
	directTransport Transport
	blockTransport  Transport
}

func NewRouter(proxyTransport Transport) *Router {
	return &Router{
		directTransport: &DirectTransport{},
		blockTransport:  &BlockTransport{},
		proxyTransport:  proxyTransport,
	}
}

func (r *Router) RouteBy(request *Request) Transport {
	if r.proxyTransport != nil {
		return r.proxyTransport
	}
	// 缺省直连模式
	return r.directTransport
}
