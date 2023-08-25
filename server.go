package mixedproxy

import (
	"context"
	"errors"
	"github.com/ido2021/mixedproxy/common"
	"github.com/ido2021/mixedproxy/socks"
	"github.com/ido2021/sysproxy"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 & http protocol
type Server struct {
	config        *Config
	listener      net.Listener
	running       bool
	closed        chan struct{}
	transport     common.Transport
	socks5        *socks.Socks5Adaptor
	router        *common.Router
	clearSysProxy func() error
}

// New creates a new Server and potentially returns an error
func New(transport common.Transport, options ...Option) *Server {
	conf := &Config{
		AuthMethods: nil,
		Credentials: nil,
		Rules:       nil,
		Rewriter:    nil,
		BindIP:      nil,
		Logger:      log.New(os.Stdout, "", log.LstdFlags),
	}

	for _, option := range options {
		option(conf)
	}

	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []socks.Authenticator{&socks.UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []socks.Authenticator{&socks.NoAuthAuthenticator{}}
		}
	}

	server := &Server{
		config:    conf,
		transport: transport,
		router:    common.NewRouter(transport),
		closed:    make(chan struct{}),
		socks5: &socks.Socks5Adaptor{
			AuthMethods: make(map[uint8]socks.Authenticator),
		},
	}

	for _, a := range conf.AuthMethods {
		server.socks5.AuthMethods[a.GetCode()] = a
	}

	return server
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	if s.running {
		return nil
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	s.listener = l
	s.running = true

	go s.serve(l)

	if s.config.SysProxy {
		s.SetSysProxy()
	}
	s.waitOnExit()
	return nil
}

func (s *Server) waitOnExit() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	select {
	case sig := <-signals:
		log.Printf("Got %s signal. Aborting...\n", sig)
		_ = s.Stop()
	case <-s.closed:
		// 不再监听信号
		signal.Stop(signals)
	}
}

// serve is used to serve connections from a listener
func (s *Server) serve(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			if !s.running {
				break
			}
			log.Println("获取连接异常：", err)
			continue
		}
		ctx := context.Background()
		go s.handleConn(ctx, conn)
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
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
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return
	}

	var adaptor common.Adaptor
	switch version[0] {
	case socks.Socks4Version:
		adaptor = common.GetAdaptor(common.SOCKS4)
	case socks.Socks5Version:
		adaptor = common.GetAdaptor(common.SOCKS5)
	default:
		adaptor = common.GetAdaptor(common.HTTP)
	}

	adaptor.HandleConn(ctx, bufConn, s.router)
}

func (s *Server) Stop() error {
	if s.running {
		s.running = false
		_ = s.ClearSysProxy()
		s.closed <- struct{}{}
		return s.listener.Close()
	}
	return nil
}

func (s *Server) SetSysProxy() error {
	if !s.running {
		return errors.New("代理未启动！")
	}
	port := s.listener.Addr().(*net.TCPAddr).Port
	clearSysProxy, err := sysproxy.SetSystemProxy(uint16(port), true)
	if err != nil {
		return err
	}
	s.clearSysProxy = clearSysProxy
	return nil
}

func (s *Server) ClearSysProxy() error {
	if s.clearSysProxy != nil {
		err := s.clearSysProxy()
		s.clearSysProxy = nil
		return err
	}
	return nil
}
