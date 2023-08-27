package common

import "encoding/json"

// Config is used to setup and configure a Server
type Config struct {
	Inbounds []Inbound `json:"inbounds"`
	Route    Route     `json:"route,omitempty"`
	Outbound *Outbound `json:"outbound,omitempty"`
	Log      Log       `json:"log,omitempty"`
}

type Inbound struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
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

type Outbound struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

type Log struct {
	Level string `json:"level,omitempty"`
}
