cmds = $(wildcard cmd/*)
binaries = $(cmds:cmd/%=bin/%)
gofiles = $(shell find pkg cmd -type f)

all: build

$(binaries): bin/%: $(gofiles) go.mod go.sum
	@echo "Building $@ ..."
	@go build -o $@ ./cmd/$*

build: $(binaries)

clean:
	rm -rf bin

test:
	go test -v ./pkg
