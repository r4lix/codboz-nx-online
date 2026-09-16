# Running in Docker (and on Unraid)

The image is published to `ghcr.io/r4lix/codboz-nx-online` for amd64 and arm64. It
contains only the static server binary on a distroless, non-root base, and the
tests run as part of every image build.

## Host networking is required

The game's matchmaking hands each player's address to the other players, who
then connect to each other directly. The server learns that address from the
connections it receives, and STUN reports it back to the player. Behind
Docker's default bridge network every connection arrives from the Docker
gateway, so every player would be told the same wrong address and peer-to-peer
play would fail.

Run the container with host networking (`--network host`), or on Unraid either
`host` or a custom `br0` network that gives the container its own LAN address.

## Choosing the STUN address

`CODBOZ_STUN_ADDRESS` (or `--stun-source-address`) is the address players use to
reach the server's UDP port.

| Where players are | Value | Router |
| --- | --- | --- |
| Your own network | `auto` (the host's LAN IPv4 and the UDP listen port) | nothing |
| Over the internet | `PUBLIC_IP:3478` | forward TCP 3074 and UDP 3478 to the host |

`auto` picks the address of the interface the host routes through. On a host
with several networks, set the address explicitly.

## docker run

```sh
docker run -d --name codboz-online --network host --restart unless-stopped \
  -e CODBOZ_STUN_ADDRESS=auto \
  -v /srv/codboz:/data \
  ghcr.io/r4lix/codboz-nx-online:latest
```

The container runs as a non-root user. The data directory must be writable by
it: either `chown 65532:65532` the directory, or run with `--user` matching the
directory's owner (Unraid: `--user 99:100`).

## docker compose

`docker-compose.yml` in the repository root does the same; edit the STUN address
and run `docker compose up -d`.

## Unraid

1. **Docker** tab, **Add Container**, then paste this into **Template**:
   `https://raw.githubusercontent.com/r4lix/codboz-nx-online/master/unraid/codboz-online.xml`
   (or copy `unraid/codboz-online.xml` to
   `/boot/config/plugins/dockerMan/templates-user/my-codboz-online.xml`).
2. Keep **Network Type** on `host`, and **STUN address** on `auto` for LAN play.
3. **Apply**. Accounts are stored in `/mnt/user/appdata/codboz-online`.

## Pointing games at it

Every player in a match must use the same server:

```text
multiplayer_server=boz-nx-online.example.org
```

An IP address works too. A DNS name is easier to hand out and survives a new
public IP, with three rules:

- The record must point **directly** at your public IP. A proxied record
  (Cloudflare's orange cloud, or any HTTP reverse proxy such as Zoraxy or
  Nginx Proxy Manager) cannot carry the game's raw TCP and UDP, and even a
  TCP/UDP stream proxy hides players' real addresses, which breaks STUN and
  peer-to-peer play.
- Forward TCP 3074 and UDP 3478 on the router straight to the Docker host.
- `CODBOZ_STUN_ADDRESS` must still be an IP (`PUBLIC_IP:3478`). If your public
  IP changes, update it along with the DNS record.

## Settings

Every flag has an environment variable; a flag on the command line wins.

| Variable | Flag | Default |
| --- | --- | --- |
| `CODBOZ_STUN_ADDRESS` | `--stun-source-address` | required (`auto` or `IPv4:PORT`) |
| `CODBOZ_DATA_DIR` | `--data-dir` | `/data` in the image |
| `CODBOZ_TCP_LISTEN` | `--tcp-listen` | `0.0.0.0:3074` |
| `CODBOZ_UDP_LISTEN` | `--udp-listen` | `0.0.0.0:3478` |
| `CODBOZ_MAX_TCP_CONNECTIONS` | `--max-tcp-connections` | `64` |
| `CODBOZ_MAX_TCP_CONNECTIONS_PER_SOURCE` | `--max-tcp-connections-per-source` | `8` |

Each online player keeps one lobby connection open, plus short-lived login
connections while signing in. Raise the per-source limit if several players
reach the server from one public address.

## Health

The image's health check runs `codboz-online-server --healthcheck`, which only
confirms that the TCP listener accepts connections. `docker ps` shows the
result.
