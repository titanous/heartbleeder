# Heartbleeder

Tests your servers for OpenSSL
[CVE-2014-0160](https://www.openssl.org/news/secadv_20140407.txt) aka
[Heartbleed](http://heartbleed.com/).

**WARNING**: This is very untested, and you should verify the results
independently. Pull requests welcome.

## Usage

```text
$ heartbleeder example.com
INSECURE - example.com:443 has the heartbeat extension enabled and is vulnerable
```

Binaries are available on the [releases
page](https://github.com/titanous/heartbleeder/releases).

Build from source by running `go get github.com/titanous/heartbleeder`, which
will put the code in `$GOPATH/src/github.com/titanous/heartbleeder` and a binary
at `$GOPATH/bin/heartbleeder`.

## Credits

The TLS implementation was borrowed from the Go standard library.
