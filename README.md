# firewallservice

На сервере ST с Ubuntu 26.04 nginx принимает `GET /firewall` по HTTPS и передаёт его сервису на Java 25. Если `name` и `password` совпадают с записью в `config.json`, сервис добавляет правило UFW для IP-адреса клиента.

## Установка на ST

```sh
git clone https://github.com/terentev/firewallservice.git
cd firewallservice
sudo ./install.sh
```

Для клонирования приватного репозитория используйте свою учётную запись GitHub или ключ с правом чтения. Установщик ставит зависимости, собирает Maven-проект, устанавливает и запускает `firewallservice.service` с автозапуском при загрузке. Java также формирует конфигурацию nginx и запускает UFW через отдельный класс с ограниченным правилом `sudo`. При первой установке скрипт создаёт `/usr/local/etc/firewallservice/config.json` со случайным токеном nginx и случайным паролем для пользователя по умолчанию. Для обновления выполните `git pull --ff-only` и `sudo ./install.sh`. Повторная установка использует существующий `config.json`.

```sh
sudoedit /usr/local/etc/firewallservice/config.json
```

В поле `"proxy.token"` хранится внутренний токен nginx из 64 строчных шестнадцатеричных символов. В объекте `"users"` хранятся пары «имя → пароль». Имена могут содержать до 64 символов из `A–Z`, `a–z`, `0–9`, `_`, `.` и `-`. Java прочитает изменения в `"users"` при следующем запросе. После изменения токена выполните `sudo ./install.sh` и примените конфигурацию nginx.

```json
{
  "proxy.token": "KEEP_THE_TOKEN_GENERATED_BY_INSTALL_SH",
  "users": {
    "joe": "REPLACE_WITH_A_LONG_RANDOM_PASSWORD",
    "mark": "REPLACE_WITH_ANOTHER_RANDOM_PASSWORD"
  }
}
```

## Удаление со ST

```sh
sudo ./uninstall.sh
```

Скрипт останавливает сервис, отключает автозапуск и удаляет JAR, unit systemd и правило `sudo`. Пакеты Ubuntu, `config.json`, системная учётная запись `firewallservice` и правила UFW сохраняются. Если файл конфигурации nginx уже создан, скрипт заменяет его заглушкой с ответом `404` для `/firewall`, чтобы действующий HTTPS-сайт мог продолжать подключать этот файл через `include`.

## nginx

Один раз добавьте строку `include` в действующий HTTPS-блок `server` для `example.com`. Установщик создаёт этот файл с настройками `/firewall` и внутренним токеном nginx. В примере ниже используются пути к сертификату Let's Encrypt.

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    include /etc/nginx/snippets/firewallservice.conf;
}
```

```sh
sudo nginx -t && sudo systemctl reload nginx
```

Java слушает `127.0.0.1:8765`. nginx передаёт значение `$remote_addr` и внутренний токен в собственных заголовках. Если перед nginx есть CDN или прокси, настройте `real_ip_header` и `set_real_ip_from` для доверенных адресов этого прокси, чтобы `$remote_addr` содержал адрес клиента. Для `/firewall` журнал доступа отключён, поскольку GET передаёт пароль в строке запроса.

## Запрос с NUC

Если с того же IP уже был `GET /firewall` за последние 30 секунд, сервис возвращает HTTP `429`. Интервал отсчитывается заново после каждого такого запроса, включая запросы с ответом `429`.

Имя `test` зарезервировано для проверки доступности. Запрос возвращает `test ok` без пароля и без изменения правил UFW.

```bash
curl --fail-with-body 'https://example.com/firewall?name=test'
```

Добавьте пользователя `joe` в объект `"users"` файла `config.json` и задайте ему пароль. Введите этот пароль, когда Bash покажет приглашение.

```bash
read -rsp 'Пароль joe: ' firewall_password
printf '\n'
printf '%s' "$firewall_password" | curl --disable --fail-with-body --silent --show-error \
  --noproxy example.com \
  --resolve example.com:443:8.8.8.8 \
  --get 'https://example.com/firewall' \
  --data-urlencode 'name=joe' \
  --data-urlencode 'password@-'
unset firewall_password
```

Чтобы передать пароль прямо в командной строке, замените `YOUR_PASSWORD` паролем пользователя `joe` из `config.json`.

```bash
curl --disable --fail-with-body --silent --show-error \
  --noproxy example.com \
  --resolve example.com:443:8.8.8.8 \
  --get 'https://example.com/firewall' \
  --data-urlencode 'name=joe' \
  --data-urlencode 'password=YOUR_PASSWORD'
```

curl проверяет цепочку доверия и имя `example.com` в сертификате. `--resolve` задаёт IP для подключения, сохраняя имя хоста для TLS. Для сертификата от собственного CA добавьте `--cacert /путь/к/ca.crt`.

При успехе ответ содержит `OK <IP>`. Сервис выполняет `ufw allow from IP comment "firewallservice NAME DATE"`, где `DATE` — время UTC, например `2026-11-22T15:30:00Z`. Правило разрешает входящий трафик с этого адреса на все порты и сохраняется до удаления. Установщик сохраняет текущий режим UFW. Правила применяются к трафику при активном UFW.

```sh
sudo ufw status numbered
sudo systemctl status firewallservice
sudo journalctl -u firewallservice -n 50
```
