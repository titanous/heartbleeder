package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] host[:443]\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
	flag.Parse()
	host := flag.Arg(0)
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	c, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		os.Exit(2)
	}

	err = c.WriteHeartbeat(1, nil)
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
	case <-time.After(*timeout):
		fmt.Printf("SECURE - %s has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)\n", host)
	}
}
