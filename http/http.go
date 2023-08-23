package http

import (
	"context"
	"fmt"
	"github.com/ido2021/mixedproxy/common"
	"log"
	"net"
	"net/http"
	"strings"
)

func init() {
	common.RegisterAdaptors(common.HTTP, &HttpAdaptor{})
}

type HttpAdaptor struct {
}

func (h *HttpAdaptor) HandleConn(ctx context.Context, conn net.Conn, router *common.Router) {
	keepAlive := true
	trusted := true // disable authenticate if cache is nil

	bufConn := common.NewBufferedConn(conn)
	for keepAlive {
		request, err := http.ReadRequest(bufConn.Reader())
		if err != nil {
			log.Println(err)
			return
		}

		request.RemoteAddr = bufConn.RemoteAddr().String()

		keepAlive = strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive"

		var resp *http.Response

		if !trusted {
			resp = authenticate(request)

			trusted = resp == nil
		}

		remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
		req := &common.Request{
			Protocol:   common.HTTP,
			RemoteAddr: &common.AddrSpec{IP: remoteAddr.IP, Port: remoteAddr.Port},
			DestAddr:   parseHTTPAddr(request),
			Conn:       bufConn,
		}

		transport := router.RouteBy(req)
		if req.DestAddr.IP == nil {
			ip, err := transport.Resolve(ctx, req.DestAddr.FQDN)
			if err != nil {
				log.Println(err)
				resp = responseWith(request, http.StatusBadGateway)
				err = resp.Write(bufConn)
				return
			}
			req.DestAddr.IP = ip
		}

		if trusted {
			// Attempt to connect
			target, err := transport.Dial(ctx, "tcp", req.DestAddr.Address())
			if err != nil {
				log.Println(err)
				return
			}

			// 隧道代理
			if request.Method == http.MethodConnect {
				// Manual writing to support CONNECT for http 1.0 (workaround for uplay client)
				if _, err = fmt.Fprintf(bufConn, "HTTP/%d.%d %03d %s\r\n\r\n", request.ProtoMajor, request.ProtoMinor, http.StatusOK, "Connection established"); err != nil {
					log.Println(err)
					break // close connection
				}

				// 无脑转发
				common.Relay(target, req.Conn)
				return
			}

			host := request.Header.Get("Host")
			if host != "" {
				request.Host = host
			}

			request.RequestURI = ""

			if isUpgradeRequest(request) {
				handleUpgrade(bufConn, request)

				return
			}

			removeHopByHopHeaders(request.Header)
			removeExtraHTTPHostPort(request)

			if request.URL.Scheme == "" || request.URL.Host == "" {
				resp = responseWith(request, http.StatusBadRequest)
			} else {
				client := newClient(transport.Dial)
				defer client.CloseIdleConnections()
				resp, err = client.Do(request)
				if err != nil {
					resp = responseWith(request, http.StatusBadGateway)
				}
			}

			removeHopByHopHeaders(resp.Header)
		}

		if keepAlive {
			resp.Header.Set("Proxy-Connection", "keep-alive")
			resp.Header.Set("Connection", "keep-alive")
			resp.Header.Set("Keep-Alive", "timeout=4")
		}

		resp.Close = !keepAlive

		err = resp.Write(bufConn)
		if err != nil {
			log.Println(err)
			break // close connection
		}
	}
}

func authenticate(request *http.Request) *http.Response {
	/*	authenticator := authStore.Authenticator()
		if authenticator != nil {
			credential := parseBasicProxyAuthorization(request)
			if credential == "" {
				resp := responseWith(request, http.StatusProxyAuthRequired)
				resp.Header.Set("Proxy-Authenticate", "Basic")
				return resp
			}

			authed, exist := cache.Get(credential)
			if !exist {
				user, pass, err := decodeBasicProxyAuthorization(credential)
				authed = err == nil && authenticator.Verify(user, pass)
				cache.Set(credential, authed)
			}
			if !authed.(bool) {
				log.Infoln("Auth failed from %s", request.RemoteAddr)

				return responseWith(request, http.StatusForbidden)
			}
		}*/

	return nil
}

func responseWith(request *http.Request, statusCode int) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Proto:      request.Proto,
		ProtoMajor: request.ProtoMajor,
		ProtoMinor: request.ProtoMinor,
		Header:     http.Header{},
	}
}
