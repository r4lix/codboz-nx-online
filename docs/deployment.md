# Deploying the server

Start by forking this repo. The rest is straightforward if you're familiar with
basic server admin and GitHub Actions.

## Requirements

- Ubuntu 24.04 x64 (This is what I used, but it should work on other Linux distributions.)
- a public IPv4 address
- TCP 3074 and UDP 3478 open to players
- SSH access as root for the initial setup

## Initial setup

Create a key for GitHub Actions:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/codboz-deploy -C codboz-deploy
```

Copy the setup files to the VPS and run the bootstrap script. Replace the
example address with the VPS IPv4 address.

```sh
export CODBOZ_VPS=203.0.113.10
ssh root@"$CODBOZ_VPS" 'install -d -m 0700 /tmp/codboz-bootstrap'
scp deploy/bootstrap.sh deploy/codboz-install deploy/codboz-online-server.service \
  root@"$CODBOZ_VPS":/tmp/codboz-bootstrap/
scp ~/.ssh/codboz-deploy.pub \
  root@"$CODBOZ_VPS":/tmp/codboz-bootstrap/deploy-key.pub
ssh root@"$CODBOZ_VPS" \
  "bash /tmp/codboz-bootstrap/bootstrap.sh '$CODBOZ_VPS:3478' /tmp/codboz-bootstrap/deploy-key.pub"
```

## GitHub Actions

Create a `production` environment in the GitHub repository and limit it to the
`master` branch. Add these secrets:

| Secret               | Value                              |
| -------------------- | ---------------------------------- |
| `DEPLOY_HOST`        | VPS IPv4 address                   |
| `DEPLOY_SSH_KEY`     | contents of `~/.ssh/codboz-deploy` |
| `DEPLOY_KNOWN_HOSTS` | SSH host-key entry for the VPS     |

Check the server's Ed25519 host-key fingerprint over a trusted SSH connection,
then generate the entry for `DEPLOY_KNOWN_HOSTS`:

```sh
ssh-keyscan -H -t ed25519 "$CODBOZ_VPS"
```

Every push to `master` now deploys the tested Linux binary. A deployment can
also be started from the Actions page.

## Checking the service

```sh
ssh root@"$CODBOZ_VPS" 'systemctl status --no-pager codboz-online-server'
ssh root@"$CODBOZ_VPS" 'ss -ltn sport = :3074; ss -lun sport = :3478'
ssh root@"$CODBOZ_VPS" \
  'journalctl -u codboz-online-server -n 100 --no-pager'
```

Point the game at the VPS:

```text
multiplayer_server=203.0.113.10
multiplayer_proxy=0
```

Registered accounts are stored under `/var/lib/codboz`. Back up that directory
if they must survive replacement of the VPS.
