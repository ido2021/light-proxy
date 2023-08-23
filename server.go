package mixedproxy

import (
	"context"
	"github.com/ido2021/mixedproxy/common"
	"github.com/ido2021/mixedproxy/socks"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 & http protocol
type Server struct {
	config    *Config
	listener  net.Listener
	running   bool
	signals   chan os.Signal
	transport common.Transport
	socks5    *socks.Socks5Adaptor
	router    *common.Router
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

	// 缺省直连模式
	if transport == nil {
		transport = new(common.DirectTransport)
	}

	server := &Server{
		config:    conf,
		transport: transport,
		signals:   make(chan os.Signal),
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
	s.waitOnExit()
	return nil
}

func (s *Server) waitOnExit() {
	signal.Notify(s.signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	sig, ok := <-s.signals
	if ok {
		log.Printf("Got %s signal. Aborting...\n", sig)
		_ = s.Stop()
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
		// 关闭信号监听通道
		signal.Stop(s.signals)
		close(s.signals)
		return s.listener.Close()
	}
	return nil
}
