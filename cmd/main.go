package main

import (
	light_proxy "github.com/ido2021/light-proxy"
	"log"
)

func main() {
	server, err := light_proxy.New("cmd/wireguard.json")
	if err != nil {
		log.Fatal(err)
	}
	err = server.Start()
	if err != nil {
		log.Fatal(err)
	}
}
