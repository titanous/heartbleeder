# Heartbleeder

Tests your servers for OpenSSL
[CVE-2014-0160](https://www.openssl.org/news/secadv_20140407.txt) aka
[Heartbleed](http://heartbleed.com/).

**WARNING**: This is very untested, and you should verify the results
independently. Pull requests welcome.

## Client Usage

to test if a server is vulnerable

```text
$ heartbleeder example.com
INSECURE - example.com:443 has the heartbeat extension enabled and is vulnerable
```

Binaries are available from
[gobuild.io](http://gobuild.io/download/github.com/titanous/heartbleeder).

Build from source by running `go get github.com/titanous/heartbleeder`, which
will put the code in `$GOPATH/src/github.com/titanous/heartbleeder` and a binary
at `$GOPATH/bin/heartbleeder`.

Requires Go version >= 1.2.

## Server Usage

to test if a client is vulnerable

```console
$ go run test_server.go
Listening on :4443
```

then a client

```console

  /usr/local/Cellar/openssl/1.0.1e/bin/openssl s_client -host localhost -port 4443
  CONNECTED
  ...
  VULNERABLE - 127.0.0.1:50918 has the heartbeat extension enabled and is vulnerable to CVE-2014-0160

```

## Credits

The TLS implementation was borrowed from the Go standard library.
