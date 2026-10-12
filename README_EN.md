# Antigravity Gate (`ag-gate`) 🚀

> **High-performance, zero-patching smart split-proxy in Rust for AI developer tools (Google Antigravity, Gemini, Cursor, Claude Code).**

[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/tests-85%20passed-brightgreen.svg)]()
[![Binary Size](https://img.shields.io/badge/binary-2.5%20MB-success.svg)]()

[Русская версия документации](README.md)

---

## ⚡ The Problem

Developers in geo-restricted regions face **HTTP 400 Bad Request ("User location is not supported")** when using AI-assisted coding tools like Google Antigravity, Gemini Code Assist, Cursor, and Claude Code.

Existing workarounds have critical flaws:
* **Global VPNs**: Degrade connection speeds for local repositories, corporate networks, banking, and streaming services.
* **Complex Tunneling Cores (sing-box, Clash)**: Require hundreds of lines of YAML/JSON routing rules and separate paid infrastructure.
* **Binary Patchers**: Modify executables on disk (`language_server.exe`), require Windows Administrator privileges for NRPT registry modifications, and break upon IDE updates or when router-level DPI bypass tools (e.g. *zapret*, *GoodbyeDPI*) are active.

---

## 💡 The Solution: Zero-Patching Smart Proxy

`antigravity-gate` is a lightweight standalone daemon written in asynchronous Rust (`tokio`):

```mermaid
graph TD
    subgraph Client ["Developer Workstation"]
        IDE["Google Antigravity / Language Server"]
        CLI["Claude Code / Cursor / Curl"]
    end

    subgraph Gate ["Antigravity Gate (127.0.0.1:1080 / 1081)"]
        SOCKS5["SOCKS5 Listener (:1080)"]
        HTTP["HTTP CONNECT Listener (:1081)"]
        SNI["Zero-Decryption TLS SNI Sniffer (RFC 6066)"]
        Router{"Smart Router"}
    end

    subgraph Outbound ["Routing Strategy"]
        GoogleNodes["Verified Overseas Google ESF SNI Pool\n(Zero-Cost, Geo-Unblocked)"]
        UpstreamProxy["Optional SOCKS5 Upstream\n(Claude / Cursor)"]
        DirectWAN["Direct Local WAN\n(GitHub, Crates.io, RuNet, etc.)"]
    end

    IDE -->|AG_LS_PROXY| HTTP
    CLI -->|ALL_PROXY| SOCKS5
    SOCKS5 --> SNI
    HTTP --> SNI
    SNI --> Router

    Router -->|*.googleapis.com| GoogleNodes
    Router -->|*.anthropic.com, *.cursor.com| UpstreamProxy
    Router -->|All other traffic| DirectWAN
```

### Key Advantages:
1. **Zero-Patching:** Never touches IDE binaries or JavaScript bundles on disk.
2. **Non-Admin:** Runs entirely in unprivileged user space — zero registry or Windows NRPT modifications.
3. **Zero-Decryption TLS SNI Sniffing:** Inspects the initial TLS `ClientHello` (RFC 6066) to route connections without generating or trusting fake CA root certificates. End-to-end encryption is 100% preserved.
4. **Active Health Check & Auto-Failover:** Continuously monitors outbound nodes against Google ESF edge points (20–70 ms latency) and automatically switches traffic upon packet loss or rate limits.
5. **DPI-Friendly:** Socket-level optimizations (`TCP_NODELAY`, pipelining resilience, graceful TCP shutdown) prevent packet desynchronization issues when combined with router-level tools like *zapret*.

---

## 🛠️ Quick Start

### 1. Build from Source
Ensure you have Rust installed (`cargo`):
```powershell
cargo build --release
```
The compiled binary will be placed at `target/release/antigravity-gate.exe` (only ~2.5 MB).

### 2. Run the Gateway
```powershell
# Run with default settings (SOCKS5 on 127.0.0.1:1080, HTTP CONNECT on 127.0.0.1:1081)
.\target\release\antigravity-gate.exe

# Or specify custom ports if 1080 is in use:
.\target\release\antigravity-gate.exe --socks5-bind 127.0.0.1:10800 --http-bind 127.0.0.1:1081

# Optional: route Claude Code / Cursor through an authenticated upstream proxy:
.\target\release\antigravity-gate.exe --upstream socks5://user:pass@127.0.0.1:40000
```

### 3. Connect Your Tools

#### Google Antigravity / Gemini Language Server:
Set the environment variable or point Antigravity's proxy settings:
```powershell
$env:AG_LS_PROXY = "http://127.0.0.1:1081"
$env:HTTPS_PROXY = "http://127.0.0.1:1081"
```

#### Terminal / CLI Tools (`claude`, `curl`, `git`):
```powershell
$env:ALL_PROXY = "socks5://127.0.0.1:1080"
$env:HTTPS_PROXY = "http://127.0.0.1:1081"
```

---

## ⚙️ CLI Options & Commands

### Subcommands:
* `serve` (default): Runs the smart proxy gateway.
* `status`: Inspects detected Antigravity installations and shows patch status.
* `patch`: Replaces `ineligible` with `inexigible` and isolates proxy lookups to `AG_LS_PROXY`.
* `unpatch`: Restores original binaries from backup or reverses byte replacements.

### Proxy Server Options:
| Flag | Default | Description |
|---|---|---|
| `-s, --socks5-bind <ADDR>` | `127.0.0.1:1080` | Local SOCKS5 bind address (fallback to `:10800` if busy) |
| `-p, --http-bind <ADDR>` | `127.0.0.1:1081` | Local HTTP CONNECT bind address (fallback to `:10801` if busy) |
| `-u, --upstream <URL>` | *None* | Optional upstream SOCKS5 proxy (`socks5://[user:pass@]host:port`) |
| `--probe-interval <SECS>` | `60` | Active health-check probe interval |
| `--auto-fallback` | `true` | Automatically try alternative port if default is occupied |
| `-v, --verbose` | *Disabled* | Enable detailed debug logging |

---

## 🧪 Testing & Code Quality

```powershell
# Run the test suite (85 unit & integration tests)
cargo test

# Run strict clippy analysis
cargo clippy --all-targets -- -D warnings
```

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.
