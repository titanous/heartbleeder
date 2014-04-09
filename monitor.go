package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var PrettyResultName = map[int]string{
	ResultSecure:            "Secure",
	ResultUnknown:           "Unknown",
	ResultConnectionRefused: "Connection Refused",
	ResultVunerable:         "Vunerable",
	ResultError:             "Unknown - errored",
}

var ResultTableRow = map[int]string{
	ResultSecure:            "success",
	ResultUnknown:           "active",
	ResultConnectionRefused: "info",
	ResultVunerable:         "danger",
	ResultError:             "active",
}

var HostMutex sync.RWMutex

type Target struct {
	Host         string
	OriginalHost string
	LastChecked  *time.Time
	TimeVerified *time.Time
	LastError    error
	State        int
}

func checkMultiHosts(hostFile string, timeout, retryDelay, refreshDelay time.Duration, numWorkers int, listenAddr string) {
	hosts := readHosts(hostFile)

	dispatch := make(chan *Target, len(hosts)*2)
	for x := 0; x < numWorkers; x++ {
		go scanner(dispatch, timeout, retryDelay)
	}

	log.Println("Serving Heartbleed status on", listenAddr)

	go feed(hosts, dispatch, retryDelay, false)
	go feed(hosts, dispatch, refreshDelay, true)

	handleHTTP(hosts, listenAddr)
}

func feed(hosts []*Target, work chan *Target, delay time.Duration, secure bool) {
	for {
		i := 0

		HostMutex.RLock()
		for _, host := range hosts {
			if secure && host.State != ResultSecure {
				continue
			} else if !secure && host.State == ResultSecure {
				continue
			}
			work <- host
			i++
		}
		HostMutex.RUnlock()

		if i > 0 {
			if secure {
				log.Printf("Submitted %d hosts for rescanning", i)
			} else {
				log.Printf("Submitted %d unfinished hosts for scanning", i)
			}
		}
		time.Sleep(delay)
	}
}

func scanner(source chan *Target, timeout, retryDelay time.Duration) {
	for target := range source {
		state, err := checkHeartbeat(target.Host, timeout, nil)
		now := time.Now()

		HostMutex.Lock()
		target.LastChecked = &now
		target.State = state
		target.LastError = err

		if target.State == ResultSecure {
			target.TimeVerified = target.LastChecked
		}
		HostMutex.Unlock()
	}
}

func NewTarget(hostaddr string) []*Target {
	host, port, err := net.SplitHostPort(hostaddr)
	if err != nil {
		host = hostaddr
		port = "443"
	}

	hostport := net.JoinHostPort(host, port)
	if net.ParseIP(host) != nil {
		return []*Target{&Target{Host: hostport, OriginalHost: hostport, State: ResultUnknown}}
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		log.Printf("Failed DNS lookup on %s. Not adding to scanner - %s", host, err)
		return nil
	}

	// Add a target for each IP so we can get an accurate view
	targets := make([]*Target, len(addrs))
	for i, addr := range addrs {
		targets[i] = &Target{Host: net.JoinHostPort(addr.String(), port), OriginalHost: hostport, State: ResultUnknown}
	}
	return targets
}

func readHosts(hostFile string) []*Target {
	var targets []*Target

	contents, err := ioutil.ReadFile(hostFile)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for _, line := range strings.Split(string(contents), "\n") {
		line := strings.TrimSpace(line)
		if line == "" {
			continue
		}
		targets = append(targets, NewTarget(line)...)
	}

	return targets
}

func handleHTTP(hosts []*Target, listenAddr string) {
	tmpl, _ := template.New("foo").Parse(`
	{{define "header"}}
	<html><head><link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css"/>
	</head>
	<body>{{end}}
	{{define "summary"}}
	<p>Total {{.Header}} hosts: <strong>{{.Count}}</strong></p>
	{{end}}
	{{define "targetrowbegin"}}
	<table class="table table-hover table-bordered">
	<tr><th>Target</th><th>IP</th><th>Checked</th>
	{{end}}
	{{define "targetrow"}}
	<tr class="{{.Style}}">
	<td>{{.Target.OriginalHost}}</td><td>{{.Target.Host}}</td><td>{{.Target.LastChecked}}</td></tr>
	{{end}}
	{{define "targetrowend"}}
	</table>
	{{end}}
	{{define "footer"}}
	</body></html>{{end}}`)

	type TargetRowContext struct {
		Target
		Style string
	}

	type SummaryContext struct {
		Header string
		Count  int
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		totals := make(map[int]int)

		for _, host := range hosts {
			totals[host.State] += 1
		}

		if r.Method != "GET" {
			http.Error(w, "Only GET is supported", http.StatusMethodNotAllowed)
			return
		}

		tmpl.ExecuteTemplate(w, "header", nil)
		for state, total := range totals {
			tmpl.ExecuteTemplate(w, "summary", SummaryContext{Header: PrettyResultName[state], Count: total})
			tmpl.ExecuteTemplate(w, "targetrowbegin", nil)
			HostMutex.RLock()
			for _, target := range hosts {
				if target.State != state {
					continue
				}
				t := TargetRowContext{
					Target: *target,
					Style:  ResultTableRow[target.State],
				}
				tmpl.ExecuteTemplate(w, "targetrow", t)
			}
			HostMutex.RUnlock()
			tmpl.ExecuteTemplate(w, "targetrowend", nil)
		}
		tmpl.ExecuteTemplate(w, "footer", nil)
	})

	http.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Only GET is supported", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		j, err := json.Marshal(hosts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(j)
	})
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
