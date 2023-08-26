package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ido2021/light-proxy/adaptor/inbound"
	common2 "github.com/ido2021/light-proxy/adaptor/inbound/common"
	"github.com/ido2021/light-proxy/common"
	"github.com/ido2021/light-proxy/route"
	"log"
	"net"
	"net/http"
	"strings"
)

func init() {
	inbound.RegisterInAdaptorFactory(inbound.HTTP, NewHttpAdaptor)
}

type HttpConfig struct {
	Address string          `json:"address"`
	Users   []*common2.User `json:"users,omitempty"`
}

type HttpAdaptor struct {
	conf     *HttpConfig
	listener net.Listener
}

func NewHttpAdaptor(config json.RawMessage) (inbound.InAdaptor, error) {
	conf := &HttpConfig{}
	err := json.Unmarshal(config, conf)
	if err != nil {
		return nil, err
	}
	return &HttpAdaptor{
		conf: conf,
	}, nil
}

func (h *HttpAdaptor) Stop() error {
	return h.listener.Close()
}

func (h *HttpAdaptor) Start(router *route.Router) error {
	l, err := net.Listen("tcp", h.conf.Address)
	if err != nil {
		return err
	}
	h.listener = l
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			// 监听关闭了，退出
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Println("获取连接异常：", err)
			continue
		}
		ctx := context.Background()
		go h.HandleConn(ctx, conn, router)
	}
	return nil
}

func (h *HttpAdaptor) HandleConn(ctx context.Context, conn net.Conn, router *route.Router) {
	var client *http.Client
	defer func() {
		if client != nil {
			client.CloseIdleConnections()
		}
	}()

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
		metadata := &common.Metadata{
			RemoteAddr: &common.AddrSpec{IP: remoteAddr.IP, Port: remoteAddr.Port},
			DestAddr:   parseHTTPAddr(request),
		}

		outAdaptor := router.Route(metadata)
		if metadata.DestAddr.IP == nil {
			ip, err := outAdaptor.Resolve(ctx, metadata.DestAddr.FQDN)
			if err != nil {
				log.Println(err)
				resp = responseWith(request, http.StatusBadGateway)
				err = resp.Write(bufConn)
				return
			}
			metadata.DestAddr.IP = ip
		}

		if trusted {
			// Attempt to connect
			target, err := outAdaptor.Dial(ctx, "tcp", metadata.DestAddr.Address())
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
				common.Relay(target, conn)
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
				if client == nil {
					client = newClient(outAdaptor.Dial)
				}
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
