package mixedproxy

import (
	"testing"

	"context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if r.Allow(ctx, &Request{Command: ConnectCommand}) {
		t.Fatalf("expect connect")
	}

	if r.Allow(ctx, &Request{Command: BindCommand}) {
		t.Fatalf("do not expect bind")
	}

	if r.Allow(ctx, &Request{Command: AssociateCommand}) {
		t.Fatalf("do not expect associate")
	}
}
