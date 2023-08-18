package mixedproxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
)

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 & http protocol
type Server struct {
	config   *Config
	listener net.Listener
	closed   bool
	socks5   *Socks5
}

// New creates a new Server and potentially returns an error
func New(options ...Option) *Server {
	conf := &Config{
		AuthMethods: nil,
		Credentials: nil,
		Resolver:    &DNSResolver{},
		Rules:       nil,
		Rewriter:    nil,
		BindIP:      nil,
		// 缺省直连模式
		DialOut: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	for _, option := range options {
		option(conf)
	}

	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	server := &Server{
		config: conf,
		socks5: &Socks5{
			authMethods: make(map[uint8]Authenticator),
		},
	}

	for _, a := range conf.AuthMethods {
		server.socks5.authMethods[a.GetCode()] = a
	}

	return server
}

// Start is used to create a listener and serve on it
func (s *Server) Start(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.closed {
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
	ctx := context.Background()
	bufConn := NewBufferedConn(conn)

	// Read the version byte
	var version []byte
	var err error
	if version, err = bufConn.Peek(1); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		return err
	}

	var request *Request
	switch version[0] {
	case socks4Version:
	case socks5Version:
		request, err = s.socks5.handshake(bufConn)
	default:
		return err
	}

	if err != nil {
		s.config.Logger.Printf("handshake failed: %v", err)
		return err
	}

	for _, rule := range s.config.Rules {
		// 不允许，直接断开连接
		if !rule.Allow(ctx, request) {
			return errors.New("rule not allowed")
		}
	}
	// Resolve the address if we have a FQDN
	dest := request.DestAddr
	if dest.FQDN != "" {
		addr, err := s.config.Resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		dest.IP = addr
	}

	switch version[0] {
	case socks4Version:
	case socks5Version:
		// Process the client request
		return s.socks5.handleRequest(ctx, request, s.config.DialOut)
	default:

	}
	return nil
}

func (s *Server) Stop() error {
	s.closed = true
	return s.listener.Close()
}
