#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "bootstrap: $*" >&2
  exit 1
}

valid_stun_address() {
  local address=$1
  local ip port octet

  ip=${address%:*}
  port=${address##*:}
  [[ $ip != "$address" && $port == 3478 ]] || return 1
  IFS=. read -r -a octets <<<"$ip"
  [[ ${#octets[@]} -eq 4 ]] || return 1
  for octet in "${octets[@]}"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

if [[ $EUID -ne 0 ]]; then
  fail "run this script as root"
fi
if [[ $# -ne 2 ]]; then
  fail "usage: bootstrap.sh PUBLIC_IPV4:3478 DEPLOY_PUBLIC_KEY"
fi

readonly stun_address=$1
readonly deploy_key=$2
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly script_dir

valid_stun_address "$stun_address" || fail "invalid public STUN address: $stun_address"
[[ -f $deploy_key && ! -L $deploy_key ]] || fail "deploy public key is missing or is not a regular file"
[[ -f $script_dir/codboz-online-server.service ]] || fail "service file is missing"
[[ -f $script_dir/codboz-install ]] || fail "installer is missing"

DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates iproute2 openssh-server sudo

if ! id codboz >/dev/null 2>&1; then
  useradd --create-home --home-dir /home/codboz --shell /bin/bash codboz
fi
passwd --lock codboz >/dev/null

install -d -o codboz -g codboz -m 0700 /home/codboz/.ssh
{
  printf 'restrict '
  cat "$deploy_key"
} >/home/codboz/.ssh/authorized_keys
chown codboz:codboz /home/codboz/.ssh/authorized_keys
chmod 0600 /home/codboz/.ssh/authorized_keys

install -d -o codboz -g codboz -m 0755 /opt/codboz /opt/codboz/bin
install -d -o codboz -g codboz -m 0700 /opt/codboz/uploads /var/lib/codboz
install -o root -g root -m 0755 "$script_dir/codboz-install" /usr/local/bin/codboz-install
install -o root -g root -m 0644 "$script_dir/codboz-online-server.service" /etc/systemd/system/codboz-online-server.service

printf 'CODBOZ_STUN_ADDRESS=%s\n' "$stun_address" >/etc/codboz-online-server.env
chown root:root /etc/codboz-online-server.env
chmod 0600 /etc/codboz-online-server.env

cat >/etc/sudoers.d/codboz-deploy <<'EOF'
codboz ALL=(root) NOPASSWD: /usr/bin/systemctl restart codboz-online-server.service
EOF
chmod 0440 /etc/sudoers.d/codboz-deploy
visudo -cf /etc/sudoers.d/codboz-deploy

systemctl daemon-reload
systemctl enable codboz-online-server.service

echo "VPS setup is complete. The service will start after the first deployment."
