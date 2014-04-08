GCC			:= gcc
CFLAGS		:=
LDFLAGS		:=
GOPATH		:= $(shell go env GOROOT)/bin:$(shell pwd)
GOOS		:= $(OS)
GOARCH		:= $(ARCH) go
GOGETTER	:= GOPATH=$(shell pwd) go get -u
GOCFLAGS	:=
GOXC		:= ./bin/goxc
MKDIR		:= mkdir
INSTALL		:= install

heartbleeder:
	go build heartbleeder.go

all:
	$(GOXC)  xc

go_get_deps:
	$(GOGETTER) github.com/laher/goxc
