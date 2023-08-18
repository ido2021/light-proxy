package mixedproxy

import (
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	server := New()
	err := server.Start("tcp", "127.0.0.1:8086")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Minute)
	server.Stop()
}
