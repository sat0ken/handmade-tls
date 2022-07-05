package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"

	//"encoding/hex"
	"flag"
	"fmt"
	"log"
)

type TLSInfo struct {
	key     []byte
	iv      []byte
	message []byte
	seqnum  uint
}

// TLSメッセージのシーケンス番号を8byteのnonceにして返す
func getNonce(i, length uint) []byte {
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
	header := tlsinfo.message[0:5]
	chiphertext := tlsinfo.message[5:]
	nonce := getNonce(tlsinfo.seqnum, 8)
	xoronce := getXORNonce(nonce, tlsinfo.iv)

	block, _ := aes.NewCipher(tlsinfo.key)
	aesgcm, _ := cipher.NewGCM(block)

	plaintext, err := aesgcm.Open(nil, xoronce, chiphertext, header)
	if err != nil {
		log.Fatalf("decrypt message err : %s\n", err)
	}
	fmt.Printf("plaintext is %x\n", plaintext[:len(plaintext)-1])
}

func strtobyte(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func main() {
	key := flag.String("key", "", "key")
	iv := flag.String("iv", "", "iv")
	enc := flag.String("enc", "", "encrypt message")
	dec := flag.String("dec", "", "decrypt message")
	seqnum := flag.Uint("seqnum", 0, "handshake message count")
	flag.Parse()

	tlsinfo := TLSInfo{
		key:    strtobyte(*key),
		iv:     strtobyte(*iv),
		seqnum: *seqnum,
	}

	if *enc != "" {
		tlsinfo.message = strtobyte(*enc)
		encryptClientMessage(tlsinfo)
	}
	if *dec != "" {
		tlsinfo.message = strtobyte(*dec)
		decryptServerMessage(tlsinfo)
	}

}
