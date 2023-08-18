package mixedproxy

import (
	"context"
	"log"
	"net"
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules []RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// DialOut function for dialing out
	DialOut func(ctx context.Context, network, addr string) (net.Conn, error)

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger
}

type Option func(*Config)

func WithDialOut(dialOut func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(config *Config) {
		config.DialOut = dialOut
	}
}

func WithResolver(resolver NameResolver) Option {
	return func(config *Config) {
		config.Resolver = resolver
	}
}

func WithCredentials(credentials CredentialStore) Option {
	return func(config *Config) {
		config.Credentials = credentials
	}
}

func WithAuthMethods(authMethods []Authenticator) Option {
	return func(config *Config) {
		config.AuthMethods = authMethods
	}
}
