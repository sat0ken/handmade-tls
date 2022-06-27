package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	conn, err := net.Dial("tcp", "127.0.0.1:8443")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print("> ")
	buffer := make([]byte, 65535)
	for {
		scanner.Scan()
		text := scanner.Text()
		packet, _ := hex.DecodeString(text)
		conn.Write(packet)

		plen, _ := conn.Read(buffer)
		fmt.Printf("recv : %x\n", buffer[:plen])
		fmt.Print("> ")
	}
	defer conn.Close()

}
