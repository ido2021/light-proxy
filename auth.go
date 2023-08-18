package mixedproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	NoAuth          = uint8(0)
	noAcceptable    = uint8(255)
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)

	// MaxAuthLen is the maximum size of user/password field in SOCKS5 Auth
	MaxAuthLen = 255
)

var (
	NoSupportedAuth = errors.New("no supported authentication mechanism")
	UserAuthFailed  = errors.New("user authentication failed")
)

// AuthContext A Request encapsulates authentication state provided
// during negotiation
type AuthContext struct {
	// Provided auth method
	Method uint8
	// Payload provided during negotiation.
	// Keys depend on the used auth method.
	// For UserPassauth contains Username
	Payload map[string]string
}

type Authenticator interface {
	Authenticate(conn net.Conn) (*AuthContext, error)
	GetCode() uint8
}

// NoAuthAuthenticator is used to handle the "No Authentication" mode
type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return NoAuth
}

func (a NoAuthAuthenticator) Authenticate(conn net.Conn) (*AuthContext, error) {
	_, err := conn.Write([]byte{socks5Version, NoAuth})
	return &AuthContext{NoAuth, nil}, err
}

// UserPassAuthenticator is used to handle username/password based
// authentication
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 {
	return UserPassAuth
}

func (a UserPassAuthenticator) Authenticate(conn net.Conn) (*AuthContext, error) {
	// Tell the client to use user/pass auth
	if _, err := conn.Write([]byte{socks5Version, UserPassAuth}); err != nil {
		return nil, err
	}

	// Get the version and username length
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	// Ensure we are compatible
	if header[0] != userAuthVersion {
		return nil, fmt.Errorf("Unsupported auth version: %v", header[0])
	}

	authBuf := make([]byte, MaxAuthLen)
	// Get username
	userLen := int(header[1])
	if userLen <= 0 {
		conn.Write([]byte{1, 1})
		return nil, UserAuthFailed
	}
	if _, err := io.ReadFull(conn, authBuf[:userLen]); err != nil {
		return nil, err
	}
	user := string(authBuf[:userLen])

	// Get password
	if _, err := conn.Read(header[:1]); err != nil {
		return nil, err
	}
	passLen := int(header[0])
	if passLen <= 0 {
		conn.Write([]byte{1, 1})
		return nil, UserAuthFailed
	}
	if _, err := io.ReadFull(conn, authBuf[:passLen]); err != nil {
		return nil, err
	}
	pass := string(authBuf[:passLen])

	// Verify the password
	if a.Credentials.Valid(user, pass) {
		if _, err := conn.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return nil, err
		}
	} else {
		if _, err := conn.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return nil, err
		}
		return nil, UserAuthFailed
	}

	// Done
	return &AuthContext{UserPassAuth, map[string]string{"Username": user}}, nil
}

// noAcceptableAuth is used to handle when we have no eligible
// authentication mechanism
func noAcceptableAuth(conn io.Writer) error {
	conn.Write([]byte{socks5Version, noAcceptable})
	return NoSupportedAuth
}
