package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s host[:443]\n", os.Args[0])
		os.Exit(2)
	}
	host := os.Args[1]
	if !strings.Contains(":", host) {
		host += ":443"
	}
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		os.Exit(2)
	}

	go func() {
		time.Sleep(10 * time.Second)
		fmt.Println("SECURE - timed out while waiting for a response from", host)
		os.Exit(0)
	}()

	_, _, err = c.Heartbeat(2, []byte{2})
	switch err {
	case nil:
		fmt.Printf("INSECURE - %s has the heartbeat extension enabled and is vulnerable\n", host)
		os.Exit(1)
	case tls.ErrNoHeartbeat:
		fmt.Printf("SECURE - %s does not have the heartbeat extension enabled\n", host)
	default:
		fmt.Printf("SECURE - %s has heartbeat extension enabled but is not vulnerable\n", host)
		fmt.Printf("This error happened while processing the heartbeat (almost certainly a good thing): %q\n", err)
	}
}
