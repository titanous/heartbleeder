package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)

var defaultTLSConfig = tls.Config{InsecureSkipVerify: true}

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
	pg := flag.Bool("pg", false, "run a check specific to Postgres TLS")
	flag.Usage = func() {
		fmt.Printf("Usage: %s [options] host[:443]\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
	flag.Parse()
	host := flag.Arg(0)

	if !strings.Contains(host, ":") {
		if *pg {
			host += ":5432"
		} else {
			host += ":443"
		}
	}
	var c *tls.Conn
	var err error
	if *pg {
		c, err = pgStartTLS(host)
	} else {
		c, err = tls.Dial("tcp", host, &defaultTLSConfig)
	}
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

func pgStartTLS(addr string) (*tls.Conn, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	// send an SSLRequest message as per Postgres protocol documentation:
	// http://www.postgresql.org/docs/9.3/static/protocol-flow.html#AEN99228
	message := make([]byte, 8)
	binary.BigEndian.PutUint32(message[:4], 8)
	binary.BigEndian.PutUint32(message[4:], 80877103)
	_, err = c.Write(message)
	if err != nil {
		return nil, fmt.Errorf("could not write to server: %v", err)
	}

	// read the response
	response := make([]byte, 1)
	_, err = io.ReadFull(c, response)
	if err != nil {
		return nil, fmt.Errorf("could not read server response: %v", err)
	}

	// if the response is not 'S', no ssl
	if response[0] != 'S' {
		return nil, fmt.Errorf("this server does not support SSL")
	}

	// otherwise, we have a connection to try to heartbeat
	return tls.Client(c, &defaultTLSConfig), nil
}
