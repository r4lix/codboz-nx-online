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

## Docker and Unraid

```sh
docker run -d --name codboz-online --network host --restart unless-stopped \
  -e CODBOZ_STUN_ADDRESS=auto -v /srv/codboz:/data \
  ghcr.io/r4lix/codboz-nx-online:latest
```

Host networking is required for peer-to-peer play. See
[docs/docker.md](docs/docker.md) for compose, the Unraid template, internet
hosting and every setting.

## Development

Go 1.26 or newer is required.

```sh
make check
make build-linux
```
