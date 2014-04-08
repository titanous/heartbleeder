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
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		os.Exit(2)
	}

	err = c.WriteHeartbeat(32, nil)
	if err == tls.ErrNoHeartbeat {
		fmt.Printf("SECURE - %s does not have the heartbeat extension enabled\n", host)
		os.Exit(0)
	}
	if err != nil {
		fmt.Println("UNKNOWN - Heartbeat enabled, but there was an error writing the payload:", err)
		os.Exit(2)
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			fmt.Printf("VULNERABLE - %s has the heartbeat extension enabled and is vulnerable to CVE-2014-0160\n", host)
			os.Exit(1)
		}
		fmt.Printf("SECURE - %s has heartbeat extension enabled but is not vulnerable\n", host)
		fmt.Printf("This error happened while reading the response to the malformed heartbeat (almost certainly a good thing): %q\n", err)
	case <-time.After(10 * time.Second):
		fmt.Printf("SECURE - %s has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)\n", host)
	}
}
