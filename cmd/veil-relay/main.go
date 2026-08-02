package main

import (
	"flag"
	"log"

	"github.com/422dev/veil/internal/relay"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:7443", "listen address")
	data := flag.String("data", "./veil-relay-data.json", "persistent relay data file")
	cert := flag.String("tls-cert", "", "TLS certificate file")
	key := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()

	store, err := relay.OpenStore(*data)
	if err != nil {
		log.Fatal(err)
	}
	server := relay.NewServer(store)
	log.Printf("veil-relay/%s listening on %s", "0.1", *addr)
	if *cert == "" {
		log.Print("warning: TLS disabled; use only on localhost or behind a TLS reverse proxy")
	}
	if err := relay.ListenAndServe(*addr, *cert, *key, server.Handler()); err != nil {
		log.Fatal(err)
	}
}
