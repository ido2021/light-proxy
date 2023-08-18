package mixedproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	ConnectCommand   = uint8(1)
	BindCommand      = uint8(2)
	AssociateCommand = uint8(3)
)

// SOCKS address types as defined in RFC 1928 section 5.
const (
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

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *AddrSpec)
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// A Request represents request received by a server
type Request struct {
	// Protocol version
	Version uint8
	// Requested command
	Command uint8
	// AuthContext provided during negotiation
	AuthContext *AuthContext
	// AddrSpec of the the network that sent the request
	RemoteAddr *AddrSpec
	// AddrSpec of the desired destination
	DestAddr *AddrSpec
	conn     net.Conn
}

//type conn interface {
//	Write([]byte) (int, error)
//	RemoteAddr() net.Addr
//}

// NewRequest creates a new Request from the tcp connection
func NewRequest(conn net.Conn) (*Request, error) {
	// Read the version byte
	header := make([]byte, 3)
	// read VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, header[:3]); err != nil {
		return nil, err
	}

	// Read in the destination address
	dest, err := readAddrSpec(conn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:  socks5Version,
		Command:  header[1],
		DestAddr: dest,
		conn:     conn,
	}

	return request, nil
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

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
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
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
	msg[0] = socks5Version
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

type closeWriter interface {
	CloseWrite() error
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(closeWriter); ok {
		_ = tcpConn.CloseWrite()
	}
	errCh <- err
}

// Relay copies between left and right bidirectionally.
func Relay(leftConn, rightConn net.Conn) {
	ch := make(chan error)

	go func() {
		_, err := io.Copy(leftConn, rightConn)
		leftConn.SetReadDeadline(time.Now())
		ch <- err
	}()

	io.Copy(rightConn, leftConn)
	rightConn.SetReadDeadline(time.Now())
	<-ch
}
