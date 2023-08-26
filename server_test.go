package light_proxy

import (
	"github.com/ido2021/light-proxy/common"
	"testing"
	"time"
)

func TestProxy(t *testing.T) {
	server := New(new(common.Direct))
	err := server.ListenAndServe("tcp", "127.0.0.1:8086")
	if err != nil {
		t.Fatal(err)
	}
	server.SysProxy(true)
	time.Sleep(5 * time.Minute)
	server.Stop()
}
