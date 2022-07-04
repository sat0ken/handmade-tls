package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	//"encoding/hex"
	"flag"
	"fmt"
	"log"
)

type TLSInfo struct {
	key []byte
	iv []byte
	message  []byte
}

// TLSメッセージのシーケンス番号を8byteのnonceにして返す
func getNonce(i, length int) []byte {
	b := make([]byte, length)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

// TLS1.3用
// https://tex2e.github.io/rfc-translater/html/rfc8446.html
// シーケンス番号とwrite_ivをxorした値がnonceになる
func getXORNonce(seqnum, writeiv []byte) []byte {
	nonce := make([]byte, len(writeiv))
	copy(nonce, writeiv)

	for i, b := range seqnum {
		nonce[4+i] ^= b
	}
	return nonce
}

func encryptClientMessage(tlsinfo TLSInfo) {
	var nonce, add []byte

	block, _ := aes.NewCipher(tlsinfo.key)
	aesgcm, _ := cipher.NewGCM(block)

	encmessage := aesgcm.Seal(nil, nonce, tlsinfo.message, add)

	fmt.Printf("message is %s\n", encmessage)

}

func decryptServerMessage(tlsinfo TLSInfo) {
	var nonce, add []byte

	block, _ := aes.NewCipher(tlsinfo.key)
	aesgcm, _ := cipher.NewGCM(block)

	plainmessage, err := aesgcm.Open(nil, nonce, tlsinfo.message, add)
	if err != nil {
		log.Fatalf("decrypt message err : %x\n", err)
	}
	fmt.Printf("message is %s\n", plainmessage)
}

func main() {
	key := flag.String("key", "", "key")
	iv := flag.String("iv", "", "iv")
	enc := flag.String("enc", "", "encrypt message")
	dec := flag.String("dec", "", "decrypt message")
	flag.Parse()

	tlsinfo := TLSInfo{
		key: []byte(*key),
		iv: []byte(*iv),
	}

	if *enc != "" {
		tlsinfo.message = []byte(*enc)
		fmt.Printf("%x\n", tlsinfo.key)
		//encryptClientMessage(tlsinfo)
	}
	if *dec != "" {
		tlsinfo.message = []byte(*enc)
		fmt.Printf("%+v\n", tlsinfo)
		//decryptServerMessage(tlsinfo)
	}

}
