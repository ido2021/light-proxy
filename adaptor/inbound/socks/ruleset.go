package socks

import (
	"context"
	"github.com/ido2021/light-proxy/common"
)

// RuleSet is used to provide custom rules to allow or prohibit actions
type RuleSet interface {
	Allow(ctx context.Context, req *common.Request) bool
}

// PermitAll returns a RuleSet which allows all types of connections
func PermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// PermitNone returns a RuleSet which disallows all types of connections
func PermitNone() RuleSet {
	return &PermitCommand{false, false, false}
}

// PermitCommand is an implementation of the RuleSet which
// enables filtering supported commands
type PermitCommand struct {
	EnableConnect   bool
	EnableBind      bool
	EnableAssociate bool
}

func (p *PermitCommand) Allow(ctx context.Context, req *common.Request) bool {
	//switch req.Command {
	//case ConnectCommand:
	//	return p.EnableConnect
	//case BindCommand:
	//	return p.EnableBind
	//case AssociateCommand:
	//	return p.EnableAssociate
	//}

	return false
}