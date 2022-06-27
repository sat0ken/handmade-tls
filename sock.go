package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"log"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	conn, err := net.Dial("tcp", "127.0.0.1:8443")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print("> ")
	for {
		scanner.Scan()
		text := scanner.Text()
		packet, _ := hex.DecodeString(text)
		conn.Write(packet)
		var b []byte
		conn.Read(b)
		fmt.Printf("recv : %x\n", b)
	}
}
