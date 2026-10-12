# Antigravity Gate (`ag-gate`) 🚀

> **Высокопроизводительный умный сплит-прокси и патчер на Rust для AI-инструментов разработчика (Google Antigravity, Gemini, Cursor, Claude Code).**

[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-85%20passed-brightgreen.svg)]()
[![Binary Size](https://img.shields.io/badge/binary-2.5%20MB-success.svg)]()

[English documentation](README_EN.md)

---

## ⚡ Проблема

Разработчики из РФ и подсанкционных регионов сталкиваются с ошибкой **HTTP 400 Bad Request ("User location is not supported")** при использовании AI-ассистентов в IDE: Google Antigravity, Gemini Code Assist, Cursor и Claude Code.

Существующие решения имеют критические минусы:
* **Глобальный VPN:** режет скорость интернета, ломает корпоративные репозитории, банки, локальную сеть и стриминги.
* **Сложные комбайны (sing-box, Clash):** требуют сотен строк JSON/YAML правил маршрутизации, ручной настройки DNS и отдельных платных серверов.
* **Старые патчеры:** модифицируют бинарники IDE на диске, требуют прав Администратора Windows для вмешательства в реестр (NRPT), ломаются при обновлениях среды разработки и конфликтуют с роутерными средствами обхода ТСПУ (*zapret*, *GoodbyeDPI*).

---

## 💡 Решение: Легковесный сплит-прокси

`antigravity-gate` — это автономный демон на асинхронном Rust (`tokio`), который выборочно направляет только AI-трафик через проверенные зарубежные узлы, оставляя весь остальной интернет прямым и быстрым:

```mermaid
graph TD
    subgraph Client ["Рабочая станция разработчика"]
        IDE["Google Antigravity / Language Server"]
        CLI["Claude Code / Cursor / Curl"]
    end

    subgraph Gate ["Antigravity Gate (127.0.0.1:1080 / 1081)"]
        SOCKS5["SOCKS5 Listener (:1080)"]
        HTTP["HTTP CONNECT Listener (:1081)"]
        SNI["Zero-Decryption TLS SNI Sniffer (RFC 6066)"]
        Router{"Умный роутер"}
    end

    subgraph Outbound ["Маршрутизация"]
        GoogleNodes["Европейский пул Google ESF SNI\n(Бесплатно, без ошибки 400)"]
        UpstreamProxy["Пользовательский SOCKS5 Upstream\n(Claude / Cursor)"]
        DirectWAN["Прямой интернет\n(GitHub, Crates.io, RuNet, игры)"]
    end

    IDE -->|AG_LS_PROXY| HTTP
    CLI -->|ALL_PROXY| SOCKS5
    SOCKS5 --> SNI
    HTTP --> SNI
    SNI --> Router

    Router -->|*.googleapis.com| GoogleNodes
    Router -->|*.anthropic.com, *.cursor.com| UpstreamProxy
    Router -->|Весь остальной трафик| DirectWAN
```

### Ключевые преимущества:
1. **Чистая сетевая работа:** не требует изменения бинарников IDE или JavaScript-бандлов на диске.
2. **Без прав Администратора:** работает полностью в пространстве обычного пользователя — никаких правок реестра Windows или политик NRPT.
3. **Безопасный SNI-анализ (Zero-Decryption):** считывает имя хоста из первого пакета TLS `ClientHello` (RFC 6066) без расшифровки трафика и без установки чужих корневых CA-сертификатов. Сквозное шифрование сохраняется на 100%.
4. **Активный Health Check и авто-переключение:** непрерывно мониторит задержку до европейских узлов Google ESF (20–70 мс) и автоматически уводит трафик со сбойных узлов.
5. **Совместимость с Zapret:** оптимизации сокетов (`TCP_NODELAY`, устойчивость к пайплайнингу, двухсторонний shutdown) исключают десинхронизацию сессий при активном zapret на роутере.

---

## 🛠️ Быстрый старт

### 1. Сборка из исходников
Для сборки потребуется установленный Rust (`cargo`):
```powershell
cargo build --release
```
Готовый бинарник будет находиться по пути: `target/release/antigravity-gate.exe` (размер всего ~2.5 МБ).

### 2. Запуск шлюза
```powershell
# Запуск с дефолтными портами (SOCKS5 на 127.0.0.1:1080, HTTP CONNECT на 127.0.0.1:1081)
.\target\release\antigravity-gate.exe

# Если порт 1080 занят (например, Telegram-прокси), укажи альтернативный порт:
.\target\release\antigravity-gate.exe --socks5-bind 127.0.0.1:10800 --http-bind 127.0.0.1:1081

# Опционально: маршрутизация Claude Code / Cursor через свой внешний SOCKS5:
.\target\release\antigravity-gate.exe --upstream socks5://user:pass@127.0.0.1:40000
```

### 3. Подключение инструментов

#### Google Antigravity / Gemini Language Server:
Задай переменную окружения перед запуском среды или в настройках прокси:
```powershell
$env:AG_LS_PROXY = "http://127.0.0.1:1081"
$env:HTTPS_PROXY = "http://127.0.0.1:1081"
```

#### Консоль и CLI-утилиты (`claude`, `curl`, `git`):
```powershell
$env:ALL_PROXY = "socks5://127.0.0.1:1080"
$env:HTTPS_PROXY = "http://127.0.0.1:1081"
```

#### Проверка работы через curl:
```powershell
# Проверка обхода Google CloudCode (возвращает 404 от европейского узла Google ESF без ошибки 400):
curl.exe -v -x http://127.0.0.1:1081 https://daily-cloudcode-pa.googleapis.com/

# Проверка прямого трафика (идёт напрямую на полной скорости провайдера):
curl.exe -v -x http://127.0.0.1:1081 https://crates.io/api/v1/crates/tokio
```

---

### 4. Разблокировка аккаунтов Google (Ineligible Account Fix)

Если твой Google-аккаунт зарегистрирован в РФ и при входе выдаёт **«Your account is ineligible for this service»**, воспользуйся встроенным патчером:

```powershell
# Проверить статус установленной IDE и бинарников:
.\target\release\antigravity-gate.exe status

# Пропатчить Antigravity для входа с ЛЮБОГО аккаунта:
.\target\release\antigravity-gate.exe patch

# Откатить изменения обратно из резервной копии (.bak):
.\target\release\antigravity-gate.exe unpatch
```

---

## ⚙️ Команды и параметры CLI

### Подкоманды:
* `serve` (по умолчанию): запуск локального прокси-сервера.
* `status`: инспекция установленного Antigravity и отображение статуса бинарников.
* `patch`: атомарная замена Protobuf-дескриптора `ineligible` $\to$ `inexigible` и изоляция переменной `AG_LS_PROXY`.
* `unpatch`: возврат оригинальных бинарников из бэкапа `.bak`.

### Параметры прокси:
| Флаг | По умолчанию | Описание |
|---|---|---|
| `-s, --socks5-bind <ADDR>` | `127.0.0.1:1080` | Адрес прослушивания SOCKS5 (автофолбэк на `:10800` при занятом порту) |
| `-p, --http-bind <ADDR>` | `127.0.0.1:1081` | Адрес прослушивания HTTP CONNECT |
| `-u, --upstream <URL>` | *None* | Внешний SOCKS5 прокси (`socks5://[user:pass@]host:port`) для Cursor/Claude |
| `--probe-interval <SECS>` | `60` | Интервал проверки доступности пула узлов (в секундах) |
| `--auto-fallback` | `true` | Автоматический выбор свободного порта, если порт по умолчанию занят |
| `-v, --verbose` | *Отключено* | Подробный вывод отладочных логов |

---

## 🧪 Тестирование и контроль качества

```powershell
# Запуск полного набора тестов (85 модульных, интеграционных и хаос-тестов)
cargo test

# Запуск строгого статического анализатора
cargo clippy --all-targets -- -D warnings
```

---

## 📄 Лицензия

Распространяется под свободной лицензией **MIT License**. См. [`LICENSE`](LICENSE) для подробностей.
