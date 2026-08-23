# cod-boz-online

Self-hosted Play Online backend for
[`cod-boz-port`](https://github.com/Producdevity/cod-boz-port).

It handles login, matchmaking, peer signaling, and endpoint
discovery. Gameplay and voice chat remain peer-to-peer. Players only meet when
they configure the same server.

Two physical devices have completed a match through this server on a routed
local network. Play across separate Internet connections still needs testing.

## Server

Running on `134.209.119.3`.


## Run locally

The server listens on TCP 3074 and UDP 3478:

```sh
go run ./cmd/codboz-online-server \
  --data-dir ./data \
  --stun-source-address 192.168.1.10:3478
```

Point each client at the same address:

```text
multiplayer_server=192.168.1.10
multiplayer_proxy=0
```

See [docs/native-online.md](docs/native-online.md) for protocol notes and
[docs/deployment.md](docs/deployment.md) for self hosting this server.

## Development

Go 1.26 or newer is required.

```sh
make check
make build-linux
```
