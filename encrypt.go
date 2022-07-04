package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

func encryptClientMessage(message, key []byte) {
	var nonce, add []byte

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)

	encmessage := aesgcm.Seal(nil, nonce, message, add)

	fmt.Printf("message is %s\n", encmessage)

}

func decryptServerMessage(message, key []byte) {
	var nonce, add []byte

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)

	plainmessage, err := aesgcm.Open(nil, nonce, message, add)
	if err != nil {
		log.Fatalf("decrypt message err : %x\n", err)
	}
	fmt.Printf("message is %s\n", plainmessage)
}

func main() {
	key := flag.String("key", "value", "key")
	enc := flag.String("enc", "", "encrypt message")
	dec := flag.String("dec", "", "decryt message")
	flag.Parse()

	privatekey, _ := hex.DecodeString(*key)
	if *enc != "" {
		encryptClientMessage([]byte(*enc), privatekey)
	}
	if *dec != "" {
		decryptServerMessage([]byte(*dec), privatekey)
	}

}
