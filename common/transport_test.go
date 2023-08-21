package common

import (
	"testing"

	"context"
)

func TestDNSResolver(t *testing.T) {
	d := &DirectTransport{}
	ctx := context.Background()

	addr, err := d.Resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !addr.IsLoopback() {
		t.Fatalf("expected loopback")
	}
}