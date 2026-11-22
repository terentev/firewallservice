#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

if (( EUID != 0 )); then
    printf 'Для установки выполните sudo ./install.sh\n' >&2
    exit 1
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
app_dir=/usr/local/lib/firewallservice
config_dir=/usr/local/etc/firewallservice
nginx_snippet=/etc/nginx/snippets/firewallservice.conf
service=firewallservice.service

if [[ ! -d /etc/nginx ]] || ! command -v nginx >/dev/null; then
    printf 'Сначала установите nginx и настройте HTTPS-сайт.\n' >&2
    exit 1
fi

exec 9>/run/firewallservice-install.lock
flock --exclusive 9
umask 022

apt-get update
apt-get install -y --no-install-recommends openjdk-25-jdk-headless maven ufw sudo

java_dir="/usr/lib/jvm/java-25-openjdk-$(dpkg --print-architecture)"
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    runuser -u "$SUDO_USER" -- env JAVA_HOME="$java_dir" mvn -B -ntp clean package
else
    JAVA_HOME="$java_dir" mvn -B -ntp clean package
fi

visudo -cf deploy/firewallservice.sudoers

if ! getent passwd firewallservice >/dev/null; then
    adduser --system --group --no-create-home --home /nonexistent firewallservice
fi

install -d -o root -g root -m 0755 "$app_dir"
install -d -o root -g firewallservice -m 0750 "$config_dir"
if [[ ! -d ${nginx_snippet%/*} ]]; then
    install -d -o root -g root -m 0755 "${nginx_snippet%/*}"
fi

staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT

if [[ ! -e $config_dir/config.json ]]; then
    "$java_dir/bin/java" -jar target/firewallservice.jar "$staging/config.json" --init-config
    install -o root -g firewallservice -m 0640 "$staging/config.json" "$config_dir/config.json.new"
    mv -fT -- "$config_dir/config.json.new" "$config_dir/config.json"
fi

chown root:firewallservice "$config_dir/config.json"
chmod 0640 "$config_dir/config.json"
"$java_dir/bin/java" -jar target/firewallservice.jar \
    "$config_dir/config.json" \
    --render-nginx deploy/nginx-firewallservice.conf > "$staging/nginx.conf"

install -o root -g root -m 0644 target/firewallservice.jar "$app_dir/firewallservice.jar.new"
if [[ -f /etc/systemd/system/$service ]]; then
    systemctl stop "$service"
fi
mv -fT -- "$app_dir/firewallservice.jar.new" "$app_dir/firewallservice.jar"
ln -sfn -- "$java_dir/bin/java" "$app_dir/java"
install -o root -g root -m 0440 deploy/firewallservice.sudoers /etc/sudoers.d/firewallservice
install -o root -g root -m 0644 "deploy/$service" "/etc/systemd/system/$service"
install -o root -g root -m 0600 "$staging/nginx.conf" "$nginx_snippet"

systemctl daemon-reload
systemctl enable "$service"
systemctl restart "$service"

printf '\nСервис установлен. Настройки пользователей лежат в %s/config.json\n' "$config_dir"
printf 'Добавьте следующую строку в блок HTTPS server.\ninclude %s;\n' "$nginx_snippet"
printf 'Затем выполните sudo nginx -t && sudo systemctl reload nginx\n'
