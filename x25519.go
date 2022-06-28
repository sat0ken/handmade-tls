package main

import (
	"fmt"
	"flag"
	"encoding/hex"
	"golang.org/x/crypto/curve25519"
)

func main() {
	in := flag.String("priv", "", "client private key")
	pub := flag.String("pub", "", "server public key")
	flag.Parse()

	privateKey, _ := hex.DecodeString(*in)
	serverPubKey, _ := hex.DecodeString(*pub)
	sharedKey, _ := curve25519.X25519(privateKey, serverPubKey)

	fmt.Printf("sharedkey is %x\n", sharedKey)
}
