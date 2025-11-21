.PHONY: run build
run:
	go run ./cmd/server
build:
	go build -o bin/iptables-web ./cmd/server
