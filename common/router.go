package common

type Router struct {
}

func (r *Router) RouteBy(request *Request) Transport {
	return &DirectTransport{}
}
