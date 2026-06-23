# domain-enrich — подробная инструкция

Офлайн-микросервис обогащения доменов: принимает список доменов и собирает по
каждому плоскую таблицу (DNS, IP, GeoIP+ASN, TLS, whois домена, network-whois,
популярность, метки угроз) **через join против заранее скачанных дампов**.
Никаких сетевых запросов в момент обработки.

---

## Содержание
1. [Как это устроено](#1-как-это-устроено)
2. [Жизненный цикл: что за чем](#2-жизненный-цикл-что-за-чем)
3. [Шаг 1. Скачать базы (`fetch-data.sh`)](#3-шаг-1-скачать-базы-fetch-datash)
4. [Шаг 2. Собрать Docker-образ](#4-шаг-2-собрать-docker-образ)
5. [Шаг 3. Запуск (lookup и batch)](#5-шаг-3-запуск-lookup-и-batch)
6. [Раскладка каталога `data/`](#6-раскладка-каталога-data)
7. [Источники данных и их свежесть](#7-источники-данных-и-их-свежесть)
8. [Схема выходной таблицы](#8-схема-выходной-таблицы)
9. [Производительность и масштаб](#9-производительность-и-масштаб)
10. [Требования к памяти](#10-требования-к-памяти)
11. [Перенос на air-gapped хост](#11-перенос-на-air-gapped-хост)
12. [Постадийный CLI, резюмируемость, `--force`](#12-постадийный-cli-резюмируемость---force)
13. [Запуск без Docker (venv)](#13-запуск-без-docker-venv)
14. [Диагностика проблем](#14-диагностика-проблем)
15. [Online-режим (live + рендер страницы)](#15-online-режим-live--рендер-страницы)

---

## 1. Как это устроено

- **Стадийный пайплайн** поверх SQLite: одна строка = один домен, каждая стадия
  дописывает свои колонки. Порядок:
  `normalize → brno → rapid7 → zone → geo → netwhois → peeringdb → rdns →
  threat → ipthreat → tranco → ct → rdap → export`.
- **Данные НЕ зашиваются в Docker-образ.** Образ маленький (~454 MB), а большие
  дампы (Brno ~16 ГБ и пр.) **монтируются** в контейнер из каталога `data/`.
- **Все источники опциональны и независимы:** нет файла источника → стадия
  пропускается с предупреждением, остальные работают.
- **Резюмируемость:** повторный запуск продолжает с места (грубо — по таблице
  `meta(stage,status)`, тонко — по per-row флагам `s_*`).
- **Офлайн гарантирован:** у runner-контейнера `network_mode: none` — сети нет
  физически.

---

## 2. Жизненный цикл: что за чем

```
[ОНЛАЙН, разово]  1. scripts/fetch-data.sh    → качает все базы в data/
[ОНЛАЙН, разово]  2. docker compose build      → собирает образ
[ОФЛАЙН, всегда]  3. ./scripts/de lookup/run   → обрабатывает, монтируя data/
```

Шаги 1–2 требуют интернета и делаются **один раз** (шаг 1 можно повторять для
обновления свежих баз). Шаг 3 работает без сети.

---

## 3. Шаг 1. Скачать базы (`fetch-data.sh`)

### Когда
Разовый подготовительный шаг **«скачать дампы»** — на машине **с интернетом**,
ДО сборки/запуска. Повторять периодически для обновления (см. свежесть в §7).

### Где запускать
На **хосте** (НЕ внутри контейнера — у него сети нет). Из любой папки — скрипт
сам переходит в корень проекта.

```bash
cd /Users/a.tsitanov/projects/domain_finder
scripts/fetch-data.sh                 # всё, включая Brno (~16 ГБ)
SKIP_BRNO=1 scripts/fetch-data.sh     # без гигантского Brno
```

- Использует `curl -C -` (**resume**): повторный запуск докачивает, не заново.
- Источники с аккаунтом/закрытые (MaxMind official, Rapid7 FDNS, ARIN/LACNIC
  bulk) НЕ качаются — для них положи файлы в `data/` вручную.

### Куда кладёт
В каталог **`data/`** в корне проекта. Это **тот же каталог, что монтируется в
контейнер** как `/data` (см. `docker-compose.yml`), поэтому «куда скачал» =
«что увидит контейнер». Раскладка — в §6.

### Размеры (для оценки места и времени)
| Файл | Размер |
|---|---|
| GeoLite2 City + ASN | ~75 МБ |
| блок-листы (URLhaus/ThreatFox/StevenBlack) | ~10 МБ |
| Tranco top-1M | ~22 МБ |
| RIR (RIPE+APNIC+AFRINIC, .gz) | ~330 МБ |
| **Brno** (4 файла) | **~16 ГБ** |

> Параллельная докачка Brno (быстрее, Zenodo троттлит на одно соединение):
> ```bash
> BASE="https://zenodo.org/api/records/14332167/files"
> for f in benign_umbrella.json benign_cesnet.json phishing.json malware.json; do
>   curl -fSL --retry 5 -C - -o "data/brno/$f" "$BASE/$f/content" &
> done; wait
> ```

### Проверка целостности (ожидаемые размеры Brno)
```bash
du -h data/brno/*.json
# benign_umbrella ≈6.1G, benign_cesnet ≈6.4G, phishing ≈2.3G, malware ≈1.1G
```

---

## 4. Шаг 2. Собрать Docker-образ

```bash
cd /Users/a.tsitanov/projects/domain_finder
docker compose build           # или: docker build -t domain-enrich:latest .
```

Образ содержит только код+зависимости (~454 MB). Данные в него НЕ входят.
Пересобирай образ после изменений кода; перекачивать данные при этом не нужно.

---

## 5. Шаг 3. Запуск (lookup и batch)

Удобная обёртка `scripts/de` = `docker compose run --rm runner …`
(entrypoint контейнера — сам CLI `domain-enrich`).

### Одно доменное досье
```bash
./scripts/de lookup ru.china-embassy.gov.cn          # полный отчёт (все разделы)
./scripts/de lookup ru.china-embassy.gov.cn --compact # скрыть пустые поля
./scripts/de lookup essex.ac.uk --json                # машинный JSON
```
По умолчанию печатаются **все 6 разделов и все поля** (пустые — `·`, как
сплошная таблица centralops): Address lookup/DNS, Domain Whois, Network Whois,
GeoIP+ASN, TLS, Popularity/Threat. `--compact` убирает пустые.

### Пакетная обработка списка
```bash
# положи список (один домен в строке) в input/
./scripts/de run --input /input/domains.txt \
                 --db /work/work.db \
                 --output /work/enriched.parquet --format both
```

- Пути `--input/--db/--output` — **внутри контейнера**: `/input`, `/work`.
- Источники (`--brno-dir`, `--maxmind-*`, `--rir-dump`, `--blocklist`, `--tranco`…)
  можно не указывать: они преднастроены через `DE_*` env в `docker-compose.yml`.
- Результат появляется в `work/` на хосте; формат `parquet|csv|both`.
- Список колонок вывода: `./scripts/de fields`.

---

## 6. Раскладка каталога `data/`

```
data/
  GeoLite2-City.mmdb            # MaxMind GeoLite2 City
  GeoLite2-ASN.mmdb             # MaxMind GeoLite2 ASN
  brno/                         # Brno: DNS+TLS+RDAP+метки
    benign_umbrella.json
    benign_cesnet.json
    phishing.json
    malware.json
  fdns.json.gz                  # (опц.) Rapid7-style forward DNS
  rdns.json.gz                  # (опц.) reverse DNS (PTR)
  rir/                          # RIR RPSL whois -> network whois
    ripe.db.inetnum.gz  ripe.db.inet6num.gz  ripe.db.organisation.gz  ripe.db.role.gz
    apnic.db.inetnum.gz apnic.db.inet6num.gz apnic.db.organisation.gz apnic.db.irt.gz apnic.db.role.gz
    afrinic.db.gz
  rdap/                         # (опц.) отдельный офлайн RDAP-дамп
  blocklists/                   # URLhaus/ThreatFox/StevenBlack/OpenPhish/Phishing.Database
  ipthreat/                     # Feodo / SSLBL / Spamhaus DROP (IP/CIDR угрозы)
  popularity/                   # tranco.csv umbrella.csv majestic_million.csv domcop_top10m.csv
  peeringdb_net.json            # PeeringDB (ASN -> org/type)
  ct/                           # (опц.) Certificate Transparency дамп -> SAN
  zones/                        # (опц.) CZDS/BIND зоны -> forward DNS
```

Чего нет — соответствующая стадия пропускается (не падает).

Соответствие env-переменных (заданы в `docker-compose.yml`):

| env | путь |
|---|---|
| `DE_BRNO_DIR` | `/data/brno` |
| `DE_MAXMIND_CITY` / `DE_MAXMIND_ASN` | `/data/GeoLite2-City.mmdb` / `…ASN.mmdb` |
| `DE_RIR_DUMP` | `/data/rir` |
| `DE_BLOCKLIST` | `/data/blocklists` |
| `DE_TRANCO` | `/data/tranco.csv` |
| `DE_RAPID7_FDNS` / `DE_RDNS_DUMP` | `/data/fdns.json.gz` / `/data/rdns.json.gz` |
| `DE_RDAP_DUMP` | `/data/rdap` |
| `DE_TRANCO` | `/data/popularity` (каталог: Tranco+Umbrella+Majestic+DomCop) |
| `DE_IPTHREAT` | `/data/ipthreat` |
| `DE_PEERINGDB` | `/data/peeringdb_net.json` |
| `DE_CT_DUMP` / `DE_ZONE` | `/data/ct` / `/data/zones` |

---

## 7. Источники данных и их свежесть

| Источник | Что даёт | Свежесть |
|---|---|---|
| **Brno (Zenodo 14332167)** | DNS, whois домена (RDAP), TLS-серты, network-whois по IP, ASN, GeoIP, **метка benign/phishing/malware** | ❗статический снимок **2024 г.**, не обновляется; ~1.1M доменов |
| **MaxMind GeoLite2** | страна/город/координаты; ASN/орг/сеть | 🟢 2×/нед |
| **abuse.ch URLhaus/ThreatFox** | вредоносные URL/домены | 🟢 непрерывно |
| **OpenPhish / Phishing.Database** | фишинговые домены | 🟢 непрерывно/ежедневно |
| **StevenBlack hosts** | реклама/трекеры/малварь | 🟢 ~ежедневно |
| **IP-угрозы: Feodo / SSLBL / Spamhaus DROP** | C2/ботнет IP, угнанные CIDR (матч по IP домена) | 🟢 ежедневно |
| **Популярность: Tranco / Umbrella / Majestic / DomCop** | ранг (берётся лучший по ансамблю) | 🟢 ежедневно |
| **PeeringDB** | имя/тип сети по ASN | 🟢 ежедневно |
| **RIR (RIPE/APNIC/AFRINIC)** | network-whois: диапазон, netname, org, страна, abuse | 🟢 ежедневно |
| **Certificate Transparency** (опц. дамп) | SAN/поддомены, TLS | зависит от дампа |
| **CZDS зоны** (опц.) | forward DNS (NS/A/AAAA) по gTLD | по заявке ICANN |
| Rapid7 FDNS | forward DNS массово | 🔴 закрыт с 2022 |
| OpenINTEL | forward/reverse DNS | 🟡 только академ. доступ |

**Вывод:** geo/ASN/угрозы/популярность/network-whois — свежие (сутки–2 нед);
DNS/whois домена/TLS из Brno — снимок 2024 г. (для домена, сменившего хостинг
после 2024, эти поля устареют). Это допустимо по ТЗ: «актуальность на сегодня
не требуется».

### Зачем нужен Brno, если есть RIR/MaxMind
Brno самодостаточен (внутри уже есть geo/asn/network-whois/TLS), но это снимок
2024 г. MaxMind/RIR/блок-листы/Tranco дают **свежий** слой и покрывают домены/IP
**вне** Brno.

---

## 8. Схема выходной таблицы

`domain, original, a, aaaa, ns, mx, txt, cname, soa, ptr, ips,
tls_cipher, tls_protocol, tls_sans,
geo_country, geo_city, geo_lat, geo_lon, asn, asn_org, asn_network, asn_type,
net_range, net_name, net_org, net_country, net_abuse_email,
popularity_rank,
registrar, registrar_ianaid, whois_server, created_date, updated_date,
expires_date, registrant_org, registrant_country, abuse_email,
domain_status, dnssec, nameservers,
threat_label, threat_type, threat_sources`

Списочные колонки (`a/aaaa/ns/mx/txt/cname/ptr/ips/nameservers/tls_sans`)
склеены через `;`. Полный список: `./scripts/de fields`.

---

## 9. Производительность и масштаб

Маргинальная стоимость на 1 домен (замерено на реальных базах):

| Стадия | Скорость | На запись |
|---|---|---|
| threat | ~16.8M rec/s | 0.06 µs |
| tranco | ~5.4M rec/s | 0.18 µs |
| GeoIP+ASN | ~71k rec/s | 14 µs |
| **netwhois** (после фикса) | **~62k rec/s** | **16 µs** |
| brno (стрим+матч) | ~12k rec/s | 81 µs |

Разовые фиксированные затраты: стрим всего Brno ~90–120 с; сборка RIR-индекса
~45–60 с; загрузка блок-листов/Tranco ~1 с.

**Проекция на 2M доменов:** весь пайплайн ≈ **4–7 минут**. (До фикса netwhois
делал линейный скан 120 мс/запись ⇒ ~67 часов; теперь бакетирование по префиксу
/16/32 ⇒ 16 µs.)

---

## 10. Требования к памяти

- RIR-индекс строится в RAM: ~2.3 ГБ (RIPE) и ~3–4 ГБ (RIPE+APNIC+AFRINIC).
- Дай **Docker Desktop ≥ 6–8 ГБ** (Settings → Resources → Memory), иначе стадия
  `netwhois` может упасть по OOM.
- Без netwhois память маленькая (mmdb/блок-листы/Tranco — десятки–сотни МБ).

---

## 11. Перенос на air-gapped хост

На машине **с интернетом**:
```bash
scripts/fetch-data.sh         # данные в data/
scripts/build-offline.sh      # → dist/domain-enrich-offline.tar.gz (образ+compose+scripts)
```
Перенести на офлайн-хост **бандл И каталог `data/`**, затем:
```bash
tar xzf domain-enrich-offline.tar.gz
docker load -i domain-enrich-image.tar
# положить рядом data/  (или примонтировать)
./scripts/de lookup example.com
```
Подробности — в `OFFLINE-README.md` внутри бандла.

---

## 12. Постадийный CLI, резюмируемость, `--force`

Каждая стадия — отдельная подкоманда поверх того же `--db`, резюмируется:
```bash
./scripts/de normalize --input /input/domains.txt --db /work/work.db
./scripts/de brno      --brno-dir /data/brno --db /work/work.db
./scripts/de geo       --maxmind-city /data/GeoLite2-City.mmdb --maxmind-asn /data/GeoLite2-ASN.mmdb --db /work/work.db
./scripts/de zone      --zone /data/zones --db /work/work.db
./scripts/de netwhois  --rir-dump /data/rir --db /work/work.db
./scripts/de peeringdb --peeringdb /data/peeringdb_net.json --db /work/work.db
./scripts/de threat    --blocklist /data/blocklists --db /work/work.db
./scripts/de ipthreat  --ipthreat /data/ipthreat --db /work/work.db
./scripts/de tranco    --tranco /data/popularity --db /work/work.db
./scripts/de ct        --ct-dump /data/ct --db /work/work.db
./scripts/de export    --db /work/work.db --output /work/enriched.parquet --format both
```

- Повторный `run` без флагов **не пересчитывает** готовое.
- Принудительно пересчитать стадию: `--force STAGE` (повторяемо), напр.
  `./scripts/de run … --force threat --force geo`.
- Прерванный процесс продолжит с места при повторном запуске.

---

## 13. Запуск без Docker (venv)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
pytest -q                       # 107 тестов
domain-enrich run --input domains.txt --db work.db --output out.parquet \
  --brno-dir ./data/brno \
  --maxmind-city ./data/GeoLite2-City.mmdb --maxmind-asn ./data/GeoLite2-ASN.mmdb \
  --rir-dump ./data/rir --blocklist ./data/blocklists --tranco ./data/tranco.csv \
  --format both
domain-enrich lookup essex.ac.uk
```

---

## 14. Диагностика проблем

| Симптом | Причина / решение |
|---|---|
| «мало данных» по домену | домена нет в дампах; без forward-DNS источника нет IP ⇒ нет geo/netwhois. Это граница offline-режима, не баг |
| `netwhois` падает / OOM | мало RAM у Docker — подними до 6–8 ГБ |
| стадия «skipped» с WARNING | нет файла источника в `data/` — это нормально, остальные стадии идут |
| `net_org` пустой у US/Amazon/Akamai IP | это ARIN-регион, бесплатного дампа ARIN нет; владельца смотри в `asn_org` (MaxMind) |
| повторный запуск ничего не меняет | стадии уже `done`; используй `--force STAGE` |
| Brno докачался не целиком | пайплайн толерантен к обрыву (обработает прочитанное); докачай `curl -C -` и перезапусти `--force brno` |
| `domain-enrich lookup` медленный | он стримит весь Brno на 1 домен; для массовой обработки используй `run` (фикс-косты амортизируются) |

---

## 15. Online-режим (live + рендер страницы)

Offline-режим джойнит домены с заранее скачанными дампами. **Online-режим**
делает ту же обработку **живыми бесплатными запросами** (скачивать базы не
нужно) и дополнительно **выкачивает отрендеренную страницу** каждого домена
через headless-браузер (Playwright). Полностью **асинхронный** (высокая
скорость) и **резюмируемый**, как offline.

### Чем отличается от offline

| | offline | online |
|---|---|---|
| Источник данных | скачанные дампы (Brno/RIR/…) | живые сервисы |
| Сеть | запрещена (`network_mode: none`) | нужна |
| Артефакт | плоская таблица | `<domain>.dossier.gz` (отчёт + HTML) + сводная таблица |
| Страница сайта | нет | да, Playwright (полный DOM после JS) |
| Скорость | I/O дампов | async, упор в rate-limit/RAM |

### Источники (все бесплатные)

| Группа | Инструмент | Ключ |
|---|---|---|
| DNS (A/AAAA/NS/MX/TXT/CNAME/SOA + PTR) | live-резолв (dnspython async) | — |
| TLS (cipher/protocol/SANs) | live TLS-handshake | — |
| Domain whois | RDAP `rdap.org/domain/<d>` | — |
| Network whois | RDAP `rdap.org/ip/<ip>` (ARIN/RIPE/APNIC) | — |
| GeoIP + ASN | MaxMind `.mmdb` (быстро) или **ip-api.com** (45/мин) | — |
| Threat | URLhaus + ThreatFox API; IP/CIDR-фиды | abuse.ch (бесплатно) |
| Popularity | Cloudflare Radar | CF token |
| **Страница** | **Playwright** (headless Chromium) | — |

DNS/RDAP/TLS почти безлимитны; узкие места — **ip-api (45/мин)** и **RAM
Playwright**. Главный рычаг скорости — **кэш запросов по IP/ASN** (сеть,
общая для многих доменов, запрашивается один раз).

### Установка

```bash
pip install -e '.[online]'
python -m playwright install chromium   # один раз скачать браузер
```

### Запуск (батч)

```bash
domain-enrich run-online \
  --input domains.txt --db work.db \
  --dossier-dir dossiers --output agg.parquet --format both \
  --concurrency 100 --render-concurrency 12 \
  --maxmind-city ./GeoLite2-City.mmdb --maxmind-asn ./GeoLite2-ASN.mmdb \
  --ipthreat ./ipthreat --abuse-key "$DE_ABUSECH_KEY"
```

- `dossiers/<domain>.dossier.gz` — `gzip(JSON)`: все поля enrichment **+**
  `page_html` **+** мета страницы (`page_path/page_http_status/page_final_url/`
  `page_bytes/page_fetched_at/page_error`). Самодостаточный файл.
- `--output` — сводная плоская таблица (как в offline), **без** `page_html`.
- Резюмируемость: убей и перезапусти — готовые домены (есть dossier / `s_render`)
  пропускаются. `--force online` (или `--force render`) — переобработать.
- `--no-render` — только enrichment, без скачивания страницы.
- Ключи опциональны: без `--abuse-key`/`--cf-token` эти стадии просто
  пропускаются. Без `--maxmind-*` гео берётся из ip-api (с rate-limit).

### Прокси-fallback при рендере (SOCKS5)

Если страница недоступна напрямую (ошибка соединения/таймаут/навигации),
рендер **повторяется через бесплатные SOCKS5-прокси** — каждая попытка в своём
браузерном контексте, **до 25 попыток** на домен. Включено по умолчанию.

- Списки тянутся с `iplocate` → при сбое с `proxifly`, парсятся в `host:port` и
  **кэшируются на диск** (`work/proxies-socks5.txt`, TTL 6 ч, env `DE_PROXY_CACHE`).
- Каждая попытка пишется в stderr: `[proxy] <domain> attempt k/25 via socks5://… : ok|<ошибка>`.
- Сработавший прокси кладётся в досье (`page_proxy`); в сводную таблицу/parquet
  он **не** попадает (только логи + JSON-досье).

| Опция | Назначение |
|---|---|
| `--no-proxy` | выключить прокси-fallback (только прямой заход) |
| `--proxy-file PATH` | взять локальный список вместо скачивания |
| `--proxy-list-url URL` | свой URL списка (повторяемо; по умолчанию iplocate+proxifly) |
| `--proxy-cache PATH` | путь кэша списка (env `DE_PROXY_CACHE`) |
| `--max-proxy-attempts N` | лимит попыток на домен (по умолчанию 25) |

```bash
# свой список прокси, не больше 10 попыток:
domain-enrich run-online --input domains.txt --db work.db \
    --proxy-file ./socks5.txt --max-proxy-attempts 10
# совсем без прокси:
domain-enrich run-online --input domains.txt --db work.db --no-proxy
```

### Чекер доступности ресурсов

Отдельная команда `check`: на вход список (по ресурсу на строку — домен/URL/IP),
на выход **два TSV-файла** — доступные и недоступные. Использует **те же
SOCKS5-прокси**: при ошибке прямого соединения пробует через прокси (до 25
попыток, лог в stderr). «Доступен» = получен **любой** HTTP-ответ (соединение
установилось), независимо от кода (200/4xx/5xx).

```bash
domain-enrich check \
  --input resources.txt \
  --success reachable.tsv --failed unreachable.tsv \
  --concurrency 100 --timeout 15
#   те же прокси-опции, что у run-online: --no-proxy / --proxy-file /
#   --proxy-list-url / --proxy-cache / --max-proxy-attempts
```

- `reachable.tsv`: `resource ⇥ status ⇥ final_url ⇥ via_proxy` (via_proxy пуст, если зашло напрямую).
- `unreachable.tsv`: `resource ⇥ attempts ⇥ error`.
- Проверка — лёгкий HTTP-запрос (HEAD, при 405/501 — GET, с follow-redirects),
  без Playwright. Нужен пакет `socksio` (входит в `.[online]` через `httpx[socks]`).

### Одно живое досье (без файлов)

```bash
domain-enrich lookup --online example.com               # все секции, живьём
domain-enrich lookup --online --render example.com --json   # + page_html в JSON
```

### Docker (отдельный сетевой сервис)

Offline-`runner` остаётся `network_mode: none`; online — отдельный сервис на
Playwright-образе **с сетью**:

```bash
docker compose --profile online build runner-online
./scripts/de-online run-online --input /input/domains.txt \
    --db /work/work.db --dossier-dir /work/dossiers \
    --output /work/agg.parquet --concurrency 100 --render-concurrency 12
./scripts/de-online lookup --online --render example.com --json
./scripts/de-online check --input /input/resources.txt \
    --success /work/reachable.tsv --failed /work/unreachable.tsv
```

### Диагностика online

| Симптом | Причина / решение |
|---|---|
| гео пустое / медленно | без MaxMind гео идёт через ip-api (45/мин); дай `--maxmind-*` |
| threat всегда пусто | нет `--abuse-key` (бесплатный на auth.abuse.ch) — стадия пропущена |
| `page_error` у многих | сайт недоступен/таймаут. Прокси-fallback включён по умолчанию (до 25 SOCKS5-попыток); смотри `[proxy] …` в stderr. Если прокси мешают/не нужны — `--no-proxy`; для RAM — `--render-concurrency` осторожно |
| все прокси-попытки падают / `[proxy] loaded 0` | бесплатные списки бывают пустые/мёртвые; дай свой `--proxy-file`, удали устаревший `work/proxies-socks5.txt` или отключи `--no-proxy` |
| Playwright «unavailable» | не выполнен `python -m playwright install chromium` |
| RDAP пусто у части доменов | у некоторых TLD нет публичного RDAP — это нормально |

---

### Ссылки на датасеты
- Brno: Zenodo record **14332167** (`https://zenodo.org/records/14332167`), CC BY 4.0
- MaxMind GeoLite2: maxmind.com (или зеркало)
- abuse.ch: urlhaus.abuse.ch, threatfox.abuse.ch
- StevenBlack hosts: github.com/StevenBlack/hosts
- Tranco: tranco-list.eu
- RIR дампы: ftp.ripe.net/ripe/dbase/split/, ftp.apnic.net/apnic/whois/, ftp.afrinic.net/pub/dbase/
