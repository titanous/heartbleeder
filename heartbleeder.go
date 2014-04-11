package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/titanous/heartbleeder/tls"
)

var defaultTLSConfig = tls.Config{InsecureSkipVerify: true}

const (
	ResultSecure = iota
	ResultUnknown
	ResultConnectionRefused
	ResultVunerable
	ResultError
)

type Dialer func(string) (*tls.Conn, error)

func main() {
	pg := flag.Bool("pg", false, "Check PostgreSQL TLS, incompatible with -hostfile")
	timeout := flag.Duration("timeout", 5*time.Second, "Timeout after sending heartbeat")
	hostFile := flag.String("hostfile", "", "Path to a newline seperated file with hosts or ips")
	workers := flag.Int("workers", runtime.NumCPU()*10, "Number of workers to scan hosts with, only used with hostfile flag")
	retryDelay := flag.Duration("retry", 10*time.Second, "Seconds to wait before retesting a host after an unfavorable response")
	refreshDelay := flag.Duration("refresh", 10*time.Minute, "Seconds to wait before rechecking secure hosts")
	listen := flag.String("listen", "localhost:5000", "Address to serve HTTP dashboard from")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] host[:443]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *hostFile != "" {
		checkMultiHosts(*hostFile, *timeout, *retryDelay, *refreshDelay, *workers, *listen)
	} else {
		if flag.NArg() != 1 {
			flag.Usage()
			os.Exit(2)
		}
		checkSingleHost(flag.Arg(0), *timeout, *pg)
	}
}

func checkSingleHost(host string, timeout time.Duration, pg bool) {
	log.SetFlags(0)
	if !strings.Contains(host, ":") {
		if pg {
			host += ":5432"
		} else {
			host += ":443"
		}
	}

	var d Dialer
	if pg {
		d = pgStartTLS
	}

	ret, _ := checkHeartbeat(host, timeout, d)
	os.Exit(ret)
}

func checkHeartbeat(host string, timeout time.Duration, dial Dialer) (int, error) {
	var err error
	var c *tls.Conn

	if dial != nil {
		c, err = dial(host)
	} else {
		c, err = tls.Dial("tcp", host, &defaultTLSConfig)
	}

	if err != nil {
		log.Printf("Error connecting to %s: %s\n", host, err)
		return ResultConnectionRefused, err
	}
	defer c.Close()

	err = c.WriteHeartbeat(1, nil)
	if err == tls.ErrNoHeartbeat {
		log.Printf("SECURE(%s) - does not have the heartbeat extension enabled", host)
		return ResultSecure, err
	}

	if err != nil {
		log.Printf("UNKNOWN(%s) - Heartbeat enabled, but there was an error writing the payload:", host, err)
		return ResultError, err
	}

	readErr := make(chan error)
	go func() {
		_, _, err := c.ReadHeartbeat()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			log.Printf("VULNERABLE(%s) - has the heartbeat extension enabled and is vulnerable to CVE-2014-0160", host)
			return ResultVunerable, err
		}
		log.Printf("SECURE(%s) has heartbeat extension enabled but is not vulnerable: %q", host, err)
		return ResultSecure, err
	case <-time.After(timeout):
	}

	log.Printf("SECURE(%s) - has the heartbeat extension enabled, but timed out after a malformed heartbeat (this likely means that it is not vulnerable)", host)
	return ResultSecure, err
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
