package socks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ido2021/light-proxy/adaptor/inbound"
	common2 "github.com/ido2021/light-proxy/adaptor/inbound/common"
	"github.com/ido2021/light-proxy/adaptor/outbound"
	"github.com/ido2021/light-proxy/common"
	"github.com/ido2021/light-proxy/route"
	"io"
	"log"
	"net"
	"strings"
)

const (
	Socks5Version = 0x05
	// MaxAddrLen is the maximum size of SOCKS address in bytes.
	MaxAddrLen = 1 + 1 + 255 + 2

	// SOCKS address types as defined in RFC 1928 section 5.
	AtypIPv4       = 0x01
	AtypDomainName = 0x03
	AtypIPv6       = 0x04
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
)

var (
	unrecognizedAddrType = errors.New("unrecognized address type")
)

func init() {
	// 注册mixed factory
	inbound.RegisterInAdaptorFactory(inbound.SOCKS5, NewSocks5Adaptor)
}

type socksRequest struct {
	metadata *common.Metadata
	cmd      byte
	auth     *common.AuthContext
}

type Sockcs5Config struct {
	Address string          `json:"address"`
	Users   []*common2.User `json:"users,omitempty"`
}

type Socks5InAdaptor struct {
	conf        *Sockcs5Config
	listener    net.Listener
	AuthMethods map[uint8]Authenticator
}

func NewSocks5Adaptor(config json.RawMessage) (inbound.InAdaptor, error) {
	conf := &Sockcs5Config{}
	err := json.Unmarshal(config, conf)
	if err != nil {
		return nil, err
	}
	return &Socks5InAdaptor{
		conf: conf,
		AuthMethods: map[uint8]Authenticator{
			NoAuth: &NoAuthAuthenticator{},
		},
	}, nil
}

func (s5 *Socks5InAdaptor) Stop() error {
	return s5.listener.Close()
}

func (s5 *Socks5InAdaptor) Start(router *route.Router) error {
	l, err := net.Listen("tcp", s5.conf.Address)
	if err != nil {
		return err
	}
	s5.listener = l
	for {
		conn, err := s5.listener.Accept()
		if err != nil {
			// 监听关闭了，退出
			if errors.Is(err, net.ErrClosed) {
				break
			}
			log.Println("获取连接异常：", err)
			continue
		}
		ctx := context.Background()
		go s5.HandleConn(ctx, conn, router)
	}
	return nil
}

func (s5 *Socks5InAdaptor) HandleConn(ctx context.Context, conn net.Conn, router *route.Router) {
	request, err := s5.handshake(conn)
	if err != nil {
		log.Println(err)
		return
	}

	outAdaptor := router.Route(request.metadata)
	// Resolve the address if we have a FQDN
	dest := request.metadata.DestAddr
	if dest.FQDN != "" && dest.IP == nil {
		addr, err := outAdaptor.Resolve(ctx, dest.FQDN)
		if err != nil {
			_ = sendReply(conn, hostUnreachable, nil)
			return
		}
		dest.IP = addr
	}

	err = s5.forwardRequest(ctx, conn, request, outAdaptor.Dial)
	if err != nil {
		log.Println(err)
	}
}

func (s5 *Socks5InAdaptor) handshake(conn net.Conn) (*socksRequest, error) {
	// Authenticate the connection
	auth, err := s5.authenticate(conn)
	if err != nil {
		err = fmt.Errorf("failed to authenticate: %v", err)
		return nil, err
	}

	// Read the version byte
	header := make([]byte, 3)
	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, header[:3]); err != nil {
		return nil, err
	}

	// Read in the destination address
	dest, err := readAddrSpec(conn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return nil, fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return nil, fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Check if this is allowed
	/*	if ctx_, ok := socks5.config.Rules.Allow(ctx, req); !ok {
			if err := sendReply(req.conn, ruleFailure, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Associate to %v blocked by rules", req.DestAddr)
		}
	*/

	request := &socksRequest{
		cmd: header[1],
		metadata: &common.Metadata{
			DestAddr: dest,
		},
		auth: auth,
	}
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.metadata.RemoteAddr = &common.AddrSpec{IP: client.IP, Port: client.Port}
	}

	return request, nil
}

// authenticate is used to handle connection authentication
func (s5 *Socks5InAdaptor) authenticate(rw net.Conn) (*common.AuthContext, error) {
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
		cator, found := s5.AuthMethods[method]
		if found {
			return cator.Authenticate(rw)
		}
	}

	// No usable method found
	return nil, noAcceptableAuth(rw)
}

// forwardRequest 转发请求
func (s5 *Socks5InAdaptor) forwardRequest(ctx context.Context, conn net.Conn, req *socksRequest, dialOut outbound.DialOut) error {
	// Switch on the command
	switch req.cmd {
	case ConnectCommand:
		return s5.handleConnect(ctx, conn, req.metadata, dialOut)
	case BindCommand:
		return s5.handleBind(ctx, conn, req.metadata)
	case AssociateCommand:
		return s5.handleAssociate(ctx, conn, req.metadata)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("unsupported command: %v", req.cmd)
	}
}

// handleConnect is used to handle a connect command
func (s5 *Socks5InAdaptor) handleConnect(ctx context.Context, conn net.Conn, metadata *common.Metadata, dialOut outbound.DialOut) error {
	// Attempt to connect
	target, err := dialOut(ctx, "tcp", metadata.DestAddr.Address())
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", metadata.DestAddr, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := common.AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	common.Relay(target, conn)

	//// ListenAndServe proxying
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
func (s5 *Socks5InAdaptor) handleBind(ctx context.Context, conn net.Conn, metadata *common.Metadata) error {
	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s5 *Socks5InAdaptor) handleAssociate(ctx context.Context, conn net.Conn, metadata *common.Metadata) error {
	// TODO: Support associate
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*common.AddrSpec, error) {
	d := &common.AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = addr
	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		d.IP = addr
	case AtypDomainName:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := uint16(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)
	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *common.AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = AtypIPv4
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = AtypDomainName
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = AtypIPv4
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = AtypIPv6
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = Socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}
