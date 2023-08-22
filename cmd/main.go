package main

import (
	"github.com/ido2021/mixedproxy"
	"github.com/ido2021/mixedproxy/common"
	"log"
)

func main() {
	server := mixedproxy.New(new(common.DirectTransport))
	err := server.ListenAndServe("tcp", "127.0.0.1:8086")
	if err != nil {
		log.Println(err)
		return
	}
	select {}
}
