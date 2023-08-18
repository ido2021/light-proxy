package mixedproxy

import "C"
import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	socks5Version = 0x05
	// MaxAddrLen is the maximum size of SOCKS address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2
)

type Dial func(ctx context.Context, network, addr string) (net.Conn, error)

type Socks5 struct {
	authMethods map[uint8]Authenticator
}

func (s5 *Socks5) handshake(conn net.Conn) (*Request, error) {
	// Authenticate the connection
	authContext, err := s5.authenticate(conn)
	if err != nil {
		err = fmt.Errorf("failed to authenticate: %v", err)
		return nil, err
	}

	request, err := NewRequest(conn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return nil, fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return nil, fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	return request, nil

}

// authenticate is used to handle connection authentication
func (s5 *Socks5) authenticate(rw net.Conn) (*AuthContext, error) {
	// Read RFC 1928 for request and reply structure and sizes.
	buf := make([]byte, MaxAddrLen)
	// read VER, NMETHODS, METHODS
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, err
	}
	// Get the methods
	nmethods := buf[1]
	if _, err := io.ReadFull(rw, buf[:nmethods]); err != nil {
		return nil, fmt.Errorf("failed to get auth methods: %v", err)
	}

	// Select a usable method
	for _, method := range buf {
		cator, found := s5.authMethods[method]
		if found {
			return cator.Authenticate(rw)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(rw)
}

// handleRequest is used for request processing after authentication
func (s5 *Socks5) handleRequest(ctx context.Context, req *Request, dialOut func(ctx context.Context, network, addr string) (net.Conn, error)) error {
	// Switch on the command
	switch req.Command {
	case ConnectCommand:
		return s5.handleConnect(ctx, req, dialOut)
	case BindCommand:
		return s5.handleBind(ctx, req)
	case AssociateCommand:
		return s5.handleAssociate(ctx, req)
	default:
		if err := sendReply(req.conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", req.Command)
	}
}

// handleConnect is used to handle a connect command
func (s5 *Socks5) handleConnect(ctx context.Context, req *Request, dialOut Dial) error {
	// Attempt to connect
	target, err := dialOut(ctx, "tcp", req.DestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(req.conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", req.DestAddr, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(req.conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	Relay(target, req.conn)

	//// Start proxying
	//errCh := make(chan error, 2)
	//go proxy(target, req.conn, errCh)
	//go proxy(req.conn, target, errCh)
	//
	//// Wait
	//for i := 0; i < 2; i++ {
	//	e := <-errCh
	//	if e != nil {
	//		// return from this function closes target (and conn).
	//		return e
	//	}
	//}
	return nil
}

// handleBind is used to handle a connect command
func (s5 *Socks5) handleBind(ctx context.Context, req *Request) error {
	// TODO: Support bind
	if err := sendReply(req.conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s5 *Socks5) handleAssociate(ctx context.Context, req *Request) error {
	// Check if this is allowed
	/*	if ctx_, ok := socks5.config.Rules.Allow(ctx, req); !ok {
			if err := sendReply(req.conn, ruleFailure, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Associate to %v blocked by rules", req.DestAddr)
		}
	*/
	// TODO: Support associate
	if err := sendReply(req.conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}
