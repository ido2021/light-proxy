package common

import "encoding/json"

// Config is used to setup and configure a Server
type Config struct {
	Listeners []Listener `json:"listeners"`
	Route     Route      `json:"route,omitempty"`
	Proxy     *Proxy     `json:"proxy,omitempty"`
	Log       Log        `json:"log,omitempty"`
}

type Listener struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type ListenerConfig interface {
	IsListenerConfig()
}

type Route struct {
	Final string `json:"final,omitempty"`
	Rules []Rule `json:"rules,omitempty"`
}

type Rule struct {
	Domain       []string `json:"domain,omitempty"`
	DomainSuffix []string `json:"domainSuffix,omitempty"`
	DomainPath   string   `json:"domainPath,omitempty"`
	Outbound     string   `json:"outbound"`
}

type Proxy struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type ProxyConfig interface {
	IsProxyConfig()
}

type Log struct {
	Level string `json:"level,omitempty"`
}
