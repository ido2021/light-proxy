package mixedproxy

import (
	"context"
	"github.com/ido2021/mixedproxy/common"
	"github.com/ido2021/mixedproxy/socks"
	"log"
	"net"
	"os"
)

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 & http protocol
type Server struct {
	config    *Config
	listener  net.Listener
	running   bool
	transport common.Transport
	socks5    *socks.Socks5
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
		socks5: &socks.Socks5{
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
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	go func() {
		err = s.Serve(l)
		if err != nil {
			log.Println("proxy server termination：", err)
		}
	}()
	return nil
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	s.running = true
	for {
		conn, err := l.Accept()
		if err != nil {
			if !s.running {
				break
			}
			log.Println("连接异常：", err)
			//conn.Close()
			continue
		}
		go s.handleConn(conn)
	}
	return nil
}

// ServeConn is used to serve a single connection.
func (s *Server) handleConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := NewBufferedConn(conn)

	// Read the version byte
	var version []byte
	var err error
	if version, err = bufConn.Peek(1); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	var request *common.Request
	switch version[0] {
	case socks.Socks4Version:
	case socks.Socks5Version:
		request, err = s.socks5.Handshake(context.Background(), bufConn)
	default:
		return err
	}
	if err != nil {
		s.config.Logger.Printf("handshake failed: %v", err)
		return err
	}

	/*	// 匹配规则找到合适的transport
		for _, rule := range s.config.Rules {
			_ = rule
		}*/

	switch version[0] {
	case socks.Socks4Version:
	case socks.Socks5Version:
		// Process the client request
		return s.socks5.HandleRequest(request, s.transport)
	default:

	}
	return nil
}

func (s *Server) Stop() error {
	s.running = false
	return s.listener.Close()
}
