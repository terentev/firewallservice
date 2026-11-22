#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

if (( $# != 0 )); then
    printf 'Запустите sudo ./uninstall.sh без аргументов.\n' >&2
    exit 2
fi

if (( EUID != 0 )); then
    printf 'Для удаления выполните sudo ./uninstall.sh\n' >&2
    exit 1
fi

app_dir=/usr/local/lib/firewallservice
config_dir=/usr/local/etc/firewallservice
nginx_snippet=/etc/nginx/snippets/firewallservice.conf
service=firewallservice.service
unit_file="/etc/systemd/system/$service"
enabled_unit="/etc/systemd/system/multi-user.target.wants/$service"

exec 9>/run/firewallservice-install.lock
flock --exclusive 9

if [[ -f $unit_file ]]; then
    systemctl disable --now "$service"
elif systemctl is-active --quiet "$service"; then
    systemctl stop "$service"
fi

rm -f -- "$unit_file" "$enabled_unit" /etc/sudoers.d/firewallservice \
    "$app_dir/firewallservice.jar" "$app_dir/firewallservice.jar.new" \
    "$app_dir/java" "$config_dir/config.json.new"
if [[ -d $app_dir ]]; then
    rmdir --ignore-fail-on-non-empty -- "$app_dir"
fi
systemctl daemon-reload

if [[ -e $nginx_snippet || -L $nginx_snippet ]]; then
    # The existing HTTPS site can still include this file.
    temporary_snippet="$(mktemp -- "${nginx_snippet%/*}/.firewallservice.XXXXXX")"
    trap 'rm -f -- "$temporary_snippet"' EXIT
    cat > "$temporary_snippet" <<'NGINX'
location = /firewall {
    access_log off;
    error_log /dev/null crit;
    return 404;
}
NGINX
    mv -fT -- "$temporary_snippet" "$nginx_snippet"

    if command -v nginx >/dev/null; then
        if ! nginx -t || { systemctl is-active --quiet nginx.service && ! systemctl reload nginx.service; }; then
            printf 'Сервис удалён. Проверьте конфигурацию nginx и выполните sudo nginx -t && sudo systemctl reload nginx\n' >&2
            exit 1
        fi
    fi
fi

printf 'Сервис удалён. Пакеты Ubuntu, настройки пользователей и правила UFW сохранены.\n'
