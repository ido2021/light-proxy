package socks

import (
	"github.com/ido2021/light-proxy/common"
	"testing"

	"context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if r.Allow(ctx, &common.Request{Command: common.ConnectCommand}) {
		t.Fatalf("expect connect")
	}

	if r.Allow(ctx, &common.Request{Command: common.BindCommand}) {
		t.Fatalf("do not expect bind")
	}

	if r.Allow(ctx, &common.Request{Command: common.AssociateCommand}) {
		t.Fatalf("do not expect associate")
	}
}
