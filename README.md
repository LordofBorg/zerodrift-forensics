# Container Live Forensics & Triage Toolkit

Скрипти для оперативного неінвазивного збору цифрових доказів (DFIR Live Triage) з контейнерів на базі Linux/Docker. Збір виконується з хоста за стандартом RFC 3227 (порядок летючості) без модифікації середовища контейнера.

## Склад репозиторію

- `live_forensics_triage.sh` — скрипт збору артефактів (пам'ять, мережа, OverlayFS upperdir, таймлайн).
- `simulate_compromise.sh` — симуляція скомпрометованого контейнера (`victim-web`) для перевірки збору.

## Швидкий старт

### 1. Симуляція атаки
Створює тестовий контейнер на базі `nginx:alpine` та симулює:
- Скидання вебшелу (`/usr/share/nginx/html/shell.sh`)
- Підміну резолвінгу в `/etc/hosts`
- Видалення конфігурації (OverlayFS whiteout)
- Безфайловий шкідливий процес (бінарник вилучено з диска, код виконується виключно в RAM)

```bash
./simulate_compromise.sh
```

### 2. Збір доказів
```bash
sudo ./live_forensics_triage.sh <CONTAINER_NAME_OR_ID> [CASE_ID]
```

Приклад:
```bash
sudo ./live_forensics_triage.sh victim-web INCIDENT_001
```

## Структура зібраних артефактів

Артефакти зберігаються в каталозі `evidence_<container>_<timestamp>/` та дублюються в компресований архів `.tar.gz`:

- `host_environment/` — базова інформація хоста (ядро, час UTC, модулі, хеш самого інструменту).
- `docker_metadata/` — `docker inspect`, логи stdout/stderr, копії bind-файлів (`hosts`, `resolv.conf`, `hostname`).
- `network/` — таблиці активних з'єднань (`ss`), інтерфейси, маршрути, ARP-таблиці та сирі `/proc/net/*` з мережевого namespace контейнера.
- `processes/` — стан процесів (`cmdline`, `environ`, `maps`, `smaps`, відкриті файлові дескриптори).
- `memory_dumps/` — відновлені виконувані файли (unlinked / deleted processes) та дампи підозрілих ділянок пам'яті (heap, stack, writable).
- `filesystem/` — повний архів верхнього шару OverlayFS (`raw_upperdir.tar.gz`) зі збереженням ACL та xattrs, таймлайн MACB (bodyfile для SleuthKit/Plaso) і реєстр вилучених файлів (OverlayFS whiteouts).
- `logs/` — лог виконання процедури збору.
- `manifest.sha256` / `manifest.md5` — контрольні суми всіх артефактів для збереження ланцюжка доказів (Chain of Custody).
- `FORENSIC_ACQUISITION_REPORT.md` — структурований звіт з результатами тріажу.

## Вимоги

- Linux з підтримкою OverlayFS і namespaces
- Docker
- Python 3 (для дампінгу пам'яті з `/proc/$PID/mem`)
