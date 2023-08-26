package mixed

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ido2021/light-proxy/adaptor/inbound"
	common2 "github.com/ido2021/light-proxy/adaptor/inbound/common"
	"github.com/ido2021/light-proxy/adaptor/inbound/http"
	"github.com/ido2021/light-proxy/adaptor/inbound/socks"
	"github.com/ido2021/light-proxy/common"
	"github.com/ido2021/light-proxy/route"
	"log"
	"net"
)

func init() {
	// 注册mixed factory
	inbound.RegisterInAdaptorFactory(inbound.MIXED, NewMixedAdaptor)
}

type MixedConfig struct {
	Address string          `json:"address"`
	Users   []*common2.User `json:"users,omitempty"`
}

type MixedAdaptor struct {
	conf     *MixedConfig
	listener net.Listener
	socks5   *socks.Socks5InAdaptor
	http     *http.HttpAdaptor
}

func NewMixedAdaptor(config json.RawMessage) (inbound.InAdaptor, error) {
	conf := &MixedConfig{}
	err := json.Unmarshal(config, conf)
	if err != nil {
		return nil, err
	}
	socks5, err := socks.NewSocks5Adaptor(config)
	if err != nil {
		return nil, err
	}
	h, err := http.NewHttpAdaptor(config)
	if err != nil {
		return nil, err
	}
	return &MixedAdaptor{
		conf:   conf,
		socks5: socks5.(*socks.Socks5InAdaptor),
		http:   h.(*http.HttpAdaptor),
	}, nil
}

func (mixed *MixedAdaptor) Start(router *route.Router) error {
	l, err := net.Listen("tcp", mixed.conf.Address)
	if err != nil {
		return err
	}
	mixed.listener = l
	for {
		conn, err := mixed.listener.Accept()
		if err != nil {
			// 监听关闭了，退出
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Println("获取连接异常：", err)
			continue
		}
		ctx := context.Background()
		go mixed.handleConn(ctx, conn, router)
	}
	return nil
}

func (mixed *MixedAdaptor) Stop() error {
	return mixed.listener.Close()
}

// ServeConn is used to serve a single connection.
func (mixed *MixedAdaptor) handleConn(ctx context.Context, conn net.Conn, router *route.Router) {
	defer func() {
		// 捕获Panic
		if err := recover(); err != nil {
			log.Println(err)
		}
		_ = conn.Close()
	}()

	conn.(*net.TCPConn).SetKeepAlive(true)

	bufConn := common.NewBufferedConn(conn)
	// Read the version byte
	version, err := bufConn.Peek(1)
	if err != nil {
		log.Println(err)
		return
	}

	switch version[0] {
	case socks.Socks4Version:
		mixed.socks5.HandleConn(ctx, bufConn, router)
	case socks.Socks5Version:
		mixed.socks5.HandleConn(ctx, bufConn, router)
	default:
		mixed.http.HandleConn(ctx, bufConn, router)
	}
}
