# VPN Control Panel

Это MVP control plane для управления VPN-подключениями через web-панель.

Теперь модель работы такая:

- `manager-api` хранит профили на диске и через Docker API поднимает отдельный runtime-контейнер на каждое подключение
- контейнер выбирается по типу VPN (`OPENVPN`, `IPSEC`, `WIREGUARD`)
- каждый runtime-контейнер живёт в собственной network namespace, а значит имеет свои маршруты, процессы и `iptables`
- сеть менеджера и сеть runtime-контейнеров разделены: `manager-web` не подключается к сети VPN runtime напрямую
- для `WIREGUARD` реализован реальный bootstrap туннеля внутри контейнера через `wg`, `ip route` и `iptables`
- для `OPENVPN` реализован запуск реального `openvpn` клиента внутри runtime-контейнера
- для `IPSEC` реализован runtime для `L2TP/IPsec PSK` через `strongSwan + xl2tpd + pppd`
- можно настраивать `Port Forwarding`: публикацию порта на хосте с пробросом в адрес/порт внутри VPN
- при старте `manager-api` восстанавливает сохранённые профили и заново синхронизирует включённые подключения
- `manager-web` показывает и желаемое состояние профиля, и реальный runtime-статус, с автообновлением и цветовой индикацией

## Компоненты

- `manager-api` — центральный API, который создаёт/останавливает runtime-контейнеры и восстанавливает состояние после перезапуска
- `manager-web` — web-интерфейс на Next.js
- `worker-runtime` — общий runtime-сервер, из которого собираются типоспецифичные образы
- `vpn-runtime-openvpn` — образ для OpenVPN runtime
- `vpn-runtime-ipsec` — образ для IPsec runtime
- `vpn-runtime-wireguard` — образ для WireGuard runtime

## Что уже реализовано

- CRUD профилей через `manager-api`
- сохранение профилей на persistent volume `manager-api-data`
- запуск отдельного контейнера на профиль по команде `connect`
- остановка и удаление контейнера по команде `disconnect`
- автоматическое восстановление профилей после перезапуска `manager-api`
- попытка восстановить только те подключения, которые были в состоянии `CONNECTED`
- отключённые профили после перезапуска остаются выключенными
- отображение runtime-контейнера, образа и реального состояния в web UI
- реальный WireGuard bootstrap внутри runtime-контейнера
- запуск OpenVPN через сырой клиентский `.ovpn`
- сохранение и повторное применение `Port Forwarding`

## Что пока остаётся ограниченным

- `IPSEC` сейчас реализован как сценарий `L2TP/IPsec PSK`, а не как полный набор всех вариантов strongSwan
- секреты пока хранятся в JSON-файле профилей и передаются в runtime через env vars
- некоторые специфичные серверные route push / policy-routing случаи всё ещё могут требовать дополнительной настройки

## Требования

- Docker Engine
- Docker Compose Plugin
- Для Windows: Docker Desktop в режиме `Linux containers`
- Для runtime-контейнеров нужен доступ к `/dev/net/tun` внутри Linux VM Docker Desktop

Проверка:

```bash
docker --version
docker compose version
```

## Запуск

### Linux / macOS / WSL

```bash
./scripts/dev-up.sh
```

### Windows PowerShell

```powershell
.\scripts\dev-up.ps1
```

### Windows CMD

```cmd
scripts\dev-up.cmd
```

После запуска будут доступны:

- Web UI: http://localhost:3000
- Manager API health: http://localhost:3001/health

## Production Compose

Для production есть отдельный compose-файл:

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d --build
```

### Параметры Runtime Окружения (prod)

Эти переменные читает `manager-api`; они влияют на создание runtime-контейнеров:

- `RUNTIME_NETWORK` (по умолчанию: `vpn-runtime-plane`) — Docker-сеть, к которой подключаются VPN runtime-контейнеры.
- `RUNTIME_PORT` (по умолчанию: `8080`) — внутренний порт runtime API.
- `RUNTIME_IMAGE_OPENVPN` (по умолчанию: `vpn-runtime-openvpn:prod`) — тег образа OpenVPN runtime.
- `RUNTIME_IMAGE_IPSEC` (по умолчанию: `vpn-runtime-ipsec:prod`) — тег образа IPsec runtime.
- `RUNTIME_IMAGE_WIREGUARD` (по умолчанию: `vpn-runtime-wireguard:prod`) — тег образа WireGuard runtime.
- `RUNTIME_STATUS_TIMEOUT_MS` (по умолчанию: `5000`) — таймаут запросов статуса runtime.
- `RUNTIME_HEALTH_TIMEOUT_MS` (по умолчанию: `30000`) — таймаут health-check запросов runtime.
- `RUNTIME_IPSEC_INTERFACE_MISSING_GRACE_MS` (по умолчанию: `300000`) — grace-период (мс) для `IPSEC/L2TP`: сколько ждать при временном исчезновении `ppp` интерфейса перед запуском recovery (`ipsec stop/restart`). Помогает избежать лишних переподключений и обрывов клиентских сессий при кратковременных сбоях канала.
- `RUNTIME_PORT_FORWARDING_MODE`:
  - `HOST` (по умолчанию в коде) — публиковать `Port Forwarding` порты на Docker-хосте.
  - `CONTAINER` (рекомендуется для изолированного доступа) — не публиковать порты на Docker-хосте; порты доступны только из контейнеров, которые могут обратиться к runtime-контейнеру по Docker-сети.

Для `RUNTIME_PORT_FORWARDING_MODE=CONTAINER` подключайтесь из другого контейнера напрямую к:

- `<runtime-container-name>:<hostPort>`

где `<runtime-container-name>` — имя runtime-контейнера профиля (например `vpn-runtime-openvpn-<profile-id>`).

Особенности production-конфигурации:

- `manager-web` запускается через `next build` + `next start`
- `manager-web` и `manager-api` не публикуют порты наружу, только `expose`
- предполагается, что внешний `nginx` подключён к сети `vpn-manager-plane`
- фронт по умолчанию использует `NEXT_PUBLIC_API_URL=/api`
- VPN runtime-контейнеры живут в отдельной сети `vpn-runtime-plane` (без `internal`, чтобы у runtime был egress к VPN endpoint)

Сетевой дизайн по умолчанию:

- `vpn-manager-plane` — сеть панели и сервисов управления
- `vpn-runtime-plane` — отдельная сеть для runtime-контейнеров VPN
- `manager-api` подключён к обеим сетям, чтобы управлять runtime и читать их статус
- `manager-web` подключён только к `vpn-manager-plane`

## Авторизация В Панели

Можно включить вход в `manager-web` через переменные окружения.

Пример для `docker-compose.yml`:

```yaml
environment:
  NEXT_PUBLIC_API_URL: http://localhost:3001
  PANEL_AUTH_USERNAME: admin
  PANEL_AUTH_PASSWORD: change-me
  PANEL_AUTH_SECRET: some-long-random-string
```

- Если `PANEL_AUTH_USERNAME` и `PANEL_AUTH_PASSWORD` пустые, вход отключён.
- `PANEL_AUTH_SECRET` рекомендуется задавать явно, чтобы cookie сессии не зависела от пароля напрямую.
- После успешного входа панель выдаёт `httpOnly` cookie и открывает основной интерфейс.
- Эти же переменные нужно передавать и в `manager-api`: тогда прямые вызовы к `/api/vpn-*` без входа в панель будут получать `401`, а браузерный фронт продолжит работать через общую cookie-сессию.

## Защита Monitoring Endpoint-ов

Для `manager-api` можно отдельно задать:

- `MONITORING_TOKEN`

Если он задан, endpoint-ы мониторинга:

- `/metrics`
- `/monitoring/status`

требуют заголовок:

```http
Authorization: Bearer <MONITORING_TOKEN>
```

Это удобно для Prometheus и Zabbix, чтобы:

- UI/API панели были защищены cookie-сессией
- monitoring не зависел от браузерного логина
- прямой доступ к метрикам без токена был закрыт

Если `MONITORING_TOKEN` не задан, monitoring endpoint-ы используют ту же cookie-аутентификацию, что и обычный API панели.

## Мониторинг Через Prometheus И Zabbix

Для простого внешнего мониторинга `manager-api` теперь отдаёт два endpoint-а:

- `GET /metrics` — Prometheus text exposition format
- `GET /monitoring/status` — JSON со сводным состоянием панели и всех профилей

Оба endpoint-а читают уже существующее состояние профилей и runtime-контейнеров, ничего дополнительно внутри `worker-runtime` настраивать не нужно.

### Prometheus

Пример scrape job:

```yaml
scrape_configs:
  - job_name: vpn_control_panel
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: change-this-monitoring-token
    static_configs:
      - targets:
          - manager-api:3001
```

Если Prometheus ходит через `nginx`, можно использовать внешний адрес:

```yaml
scrape_configs:
  - job_name: vpn_control_panel
    metrics_path: /api/metrics
    scheme: https
    authorization:
      type: Bearer
      credentials: change-this-monitoring-token
    static_configs:
      - targets:
          - vcp.example.com
```

Основные метрики:

- `vpn_control_plane_up` — `manager-api` отвечает
- `vpn_control_plane_startup_state{state="..."}` — состояние запуска (`BOOTING`, `RECONCILING`, `READY`, `ERROR`)
- `vpn_profiles_total` — общее количество профилей
- `vpn_profiles_desired_total{state="CONNECTED|STOPPED|ERROR"}` — desired state профилей
- `vpn_runtime_containers_running` — количество реально запущенных runtime-контейнеров
- `vpn_workers_connected` — количество реально подключённых VPN runtime
- `vpn_workers_problem` — количество проблемных runtime (`ERROR`, `DEGRADED`, `UNREACHABLE`, `STOPPED`)
- `vpn_profile_desired_connected{profile_id="...",profile_name="...",type="...",host="..."}` — профиль должен быть подключён
- `vpn_runtime_container_running{...}` — контейнер реально запущен
- `vpn_worker_connected{...}` — worker реально в состоянии `CONNECTED`
- `vpn_worker_problem{...}` — worker в проблемном состоянии
- `vpn_port_forwarding_applied{...}` — Port Forwarding применён
- `vpn_firewall_applied{...}` — firewall применён
- `vpn_profile_last_handshake_age_seconds{...}` — сколько секунд прошло с последнего handshake
- `vpn_profile_last_handshake_timestamp_seconds{...}` — timestamp последнего handshake

### Zabbix

Самый простой способ — использовать `HTTP agent` item на endpoint:

- `/monitoring/status`

Пример внешнего URL через `nginx`:

- `https://vcp.example.com/api/monitoring/status`

Для запроса нужно передавать заголовок:

```http
Authorization: Bearer <MONITORING_TOKEN>
```

Что удобно забирать из JSON:

- `$.service.startupState`
- `$.service.startupError`
- `$.summary.totalProfiles`
- `$.summary.desiredConnected`
- `$.summary.runningContainers`
- `$.summary.connectedWorkers`
- `$.summary.workerProblems`

Если нужны данные по конкретному профилю, удобно использовать LLD или dependent items по массиву `profiles`.

Пример структуры ответа:

```json
{
  "service": {
    "name": "manager-api",
    "startupState": "READY",
    "startupError": null,
    "persistenceReady": true,
    "generatedAt": "2026-03-31T12:00:00.000Z"
  },
  "summary": {
    "totalProfiles": 2,
    "desiredConnected": 1,
    "desiredStopped": 1,
    "desiredError": 0,
    "runningContainers": 1,
    "connectedWorkers": 1,
    "workerProblems": 0
  },
  "profiles": [
    {
      "profileId": "uuid",
      "name": "ovpn",
      "type": "OPENVPN",
      "host": "vpn.example.com",
      "port": 7050,
      "managerStatus": "CONNECTED",
      "runtimeContainerState": "running",
      "workerStatus": "CONNECTED",
      "firewallStatus": "NOT_CONFIGURED",
      "portForwardingStatus": "APPLIED",
      "lastHandshakeAt": "2026-03-31T11:59:30.000Z",
      "workerLastMessage": "OpenVPN tunnel is active on tap0",
      "lastError": null
    }
  ]
}
```

### Рекомендация По Публикации Endpoint-ов

Если панель стоит за `nginx`, удобная схема такая:

- `/` -> `manager-web`
- `/api/` -> `manager-api`

Тогда monitoring endpoint-ы будут доступны как:

- `/api/metrics`
- `/api/monitoring/status`

Если эти данные не должны быть доступны публично, лучше ограничить доступ к ним:

- по IP
- через basic auth на уровне `nginx`
- или публиковать их только во внутренней сети мониторинга

## Перезапуск и восстановление

Поведение после перезапуска теперь такое:

- профили сохраняются в `PROFILE_STORE_PATH` внутри volume `manager-api-data`
- если профиль был `CONNECTED`, `manager-api` на старте либо подхватит уже живой runtime-контейнер, либо создаст его заново
- если профиль был `STOPPED`, он останется выключенным
- если восстановление не удалось, профиль перейдёт в `ERROR`, а причина отобразится в панели

Важно: `docker compose down` по умолчанию не удаляет volume, поэтому настройки сохраняются между перезапусками. Если удалить volume вручную, профили исчезнут.

## Создание OpenVPN-подключения

При создании профиля типа `OPENVPN` можно указать:

- `OpenVPN .ovpn config` — полный клиентский конфиг
- `OpenVPN username` — опционально
- `OpenVPN password` — опционально
- `ca.crt`
- `client.crt`
- `client.key`
- `tls-auth key` — опционально
- `key-direction` — например `1`

Runtime сам создаёт временные файлы внутри контейнера и переписывает `ca/cert/key/tls-auth` пути из конфига на Linux-пути внутри контейнера.

Если в `.ovpn` используется `auth-user-pass`, runtime автоматически подставит файл с логином/паролем.

## Создание IPsec/L2TP-подключения

При создании профиля типа `IPSEC` указываются:

- `Endpoint host` — адрес VPN-сервера
- `Port` — обычно `500`
- `L2TP username`
- `L2TP password`
- `IPsec PSK`
- `Remote identifier` — опционально, если сервер требует конкретный `rightid`
- `Local identifier` — опционально
- `DNS servers` — опционально
- `MTU/MRU` — по умолчанию `1410`

Runtime внутри контейнера:

- поднимает `strongSwan`
- создаёт transport-mode `IPsec` соединение для `L2TP`
- запускает `xl2tpd`
- поднимает `ppp0`
- после этого применяет `iptables` и `Port Forwarding`

## Проверка OpenVPN + RDP

Это хороший сценарий для первичной проверки:

1. Создайте профиль типа `OPENVPN`
2. Вставьте рабочий `.ovpn`
3. Если сервер требует логин/пароль, укажите их
4. В блоке `Port Forwarding` добавьте правило:
   - `Protocol`: `tcp`
   - `Host port`: например `13389`
   - `Target IP`: адрес RDP-хоста внутри VPN
   - `Target port`: `3389`
5. Нажмите `Connect`
6. Подключитесь с хоста к `localhost:13389`

Ожидаемо:

- OpenVPN runtime выходит в `CONNECTED`
- внутри контейнера поднимается `tun0`
- правила `DNAT/FORWARD/MASQUERADE` применяются
- RDP-трафик с хоста доходит до машины внутри VPN

## Создание реального WireGuard-подключения

При создании профиля типа `WIREGUARD` заполняются:

- `Endpoint host` — IP или hostname удалённого WireGuard peer
- `Endpoint port` — обычно `51820`
- `Tunnel address` — адрес интерфейса контейнера, например `10.8.0.2/32`
- `Private key` — приватный ключ клиента
- `Peer public key` — публичный ключ сервера
- `Preshared key` — опционально
- `Allowed IPs` — список через запятую, например `0.0.0.0/0` или `10.0.0.0/24,192.168.0.0/16`
- `Persistent keepalive` — например `25`
- `DNS servers` — пока только сохраняются и логируются, автоматически в `resolv.conf` не применяются

## Port Forwarding

Теперь в профиле есть отдельный блок `Port Forwarding`.

Каждое правило описывает:

- `Protocol` — `tcp` или `udp`
- `Host port` — входной порт правила (`HOST`: публикуется на Docker host, `CONTAINER`: доступен только через сеть runtime-контейнера)
- `Target IP` — адрес в VPN-сети клиента
- `Target port` — порт на целевой машине в VPN
- `Description` — произвольная пометка

Под капотом это делает:

- публикацию `Host port` на runtime-контейнере (и на хосте только в режиме `RUNTIME_PORT_FORWARDING_MODE=HOST`)
- маршрут до `Target IP` через VPN-интерфейс
- `DNAT`
- `FORWARD`
- `MASQUERADE`

Эти правила сохраняются в профиле и автоматически применяются заново:

- при обычном старте инстанса
- после восстановления WireGuard-соединения
- после перезапуска `manager-api`

## Как проверить восстановление

1. Создайте два профиля
2. Один подключите, второй оставьте выключенным
3. Перезапустите `manager-api` или весь `docker compose up`
4. Откройте UI

Ожидаемо:

- подключённый профиль снова окажется в рабочем runtime-состоянии
- выключенный профиль останется `STOPPED`
- в таблице `Инстансы` отобразятся:
  - желаемое состояние
  - состояние контейнера
  - реальный runtime-статус

## Как проверить WireGuard

1. Откройте `http://localhost:3000`
2. Создайте профиль типа `WIREGUARD`
3. Нажмите `Connect`
4. Убедитесь, что у профиля появился свой `runtime container`
5. Проверьте, что в таблице статус стал `CONNECTED`
6. Откройте Docker Desktop и найдите контейнер `vpn-runtime-wireguard-...`
7. Внутри контейнера проверьте:

```bash
ip addr show wg0
wg show
ip route
iptables -S
```

Ожидаемо:

- интерфейс `wg0` существует
- `wg show` показывает peer и handshake после обмена трафиком
- маршруты на `Allowed IPs` указывают на `wg0`
- правила `iptables` созданы внутри namespace контейнера

## Остановка

### Linux / macOS / WSL

```bash
./scripts/dev-down.sh
```

### Windows PowerShell

```powershell
.\scripts\dev-down.ps1
```

### Windows CMD

```cmd
scripts\dev-down.cmd
```

Динамически созданные runtime-контейнеры отключаются через API-команду `disconnect` или удалением профиля.

## Ограничения текущей реализации WireGuard

- конфигурация хранится в JSON-файле volume `manager-api-data`, без полноценного секрета-хранилища
- секреты передаются в runtime-контейнер через env vars
- default route для `0.0.0.0/0` настраивается упрощённо, без полной policy-routing схемы как в `wg-quick`
- DNS пока не переписывается автоматически
- если среда Docker Desktop не даёт нужный доступ к WireGuard/TUN, контейнер перейдёт в `ERROR`

## Следующий этап

### WireGuard

- хранение секретов вне UI DTO
- нормальная policy routing схема для full-tunnel
- автогенерация `resolv.conf`
- health-check по реальному handshake и трафику

### OpenVPN runtime

- генерация runtime-конфига
- запуск `openvpn` через `child_process.spawn`
- чтение management interface OpenVPN

### IPsec runtime

- работа через `swanctl`
- либо интеграция с strongSwan VICI

### Manager API

- шифрование секрета на диске
- аудит
- WebSocket-обновления вместо polling
