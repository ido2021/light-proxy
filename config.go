package mixedproxy

import (
	"github.com/ido2021/mixedproxy/common"
	"github.com/ido2021/mixedproxy/socks"
	"log"
	"net"
)

// Config is used to setup and configure a Server
type Config struct {
	// 系统代理
	SysProxy bool
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []socks.Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials socks.CredentialStore

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules []socks.RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter common.AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger
}

type Option func(*Config)

func WithCredentials(credentials socks.CredentialStore) Option {
	return func(config *Config) {
		config.Credentials = credentials
	}
}

func WithAuthMethods(authMethods []socks.Authenticator) Option {
	return func(config *Config) {
		config.AuthMethods = authMethods
	}
}
