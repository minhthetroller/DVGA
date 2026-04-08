# DVGA — Deliberately Vulnerable Go Application

A purposely insecure web application for learning and practising web security concepts.  
It covers **5 OWASP Top 10 (2021)** categories, each with **Easy / Medium / Hard** difficulty modes and a **4-level progressive hint system** so learners can work at their own pace.

> **Warning — for educational use only. Never deploy this on a public network.**

---

## Table of Contents

- [Features](#features)
- [Vulnerability Modules](#vulnerability-modules)
- [Getting Started](#getting-started)
  - [Docker (recommended)](#docker-recommended)
  - [Go directly](#go-directly)
- [Usage](#usage)
- [Architecture](#architecture)
- [Database](#database)
- [Configuration](#configuration)
- [Development](#development)

---

## Features

- 14 vulnerability modules across 5 OWASP Top 10 categories
- Per-module **Easy → Medium → Hard** difficulty progression
- **4-level progressive hints** revealed on demand (no spoilers unless you ask)
- Realistic-looking UI — vulnerabilities are disguised as normal application features
- SQLite database, no external services required
- Docker Compose for zero-config setup

---

## Vulnerability Modules

| Module | ID | OWASP Category | What it demonstrates |
|---|---|---|---|
| Employee Directory | `sqli` | A03 Injection | SQL Injection: string concatenation → quote escaping → parameterized queries |
| Username Availability | `sqli-blind` | A03 Injection | Blind SQLi: boolean & time-based → escaping bypass → secure queries |
| Network Diagnostics | `cmdi` | A03 Injection | Command Injection: shell -c → blacklist bypass → strict IP regex |
| Product Search | `xss-reflected` | A03 Injection | Reflected XSS: no filtering → `<script>` stripping bypass → HTML escape + CSP |
| Customer Reviews | `xss-stored` | A03 Injection | Stored XSS: raw storage → tag strip bypass → escape on render |
| My Profile | `idor` | A01 Broken Access Control | IDOR: no auth check → client-side cookie → server-side session |
| Document Library | `path-traversal` | A01 Broken Access Control | Path Traversal: no sanitization → `../` strip bypass → `filepath.Clean` + bounds |
| Team Management | `privesc` | A01 Broken Access Control | Privilege Escalation: no role check → client cookie → server-side session role |
| Secure Notes | `data-exposure` | A02 Cryptographic Failures | Data Exposure: plaintext → Base64 → AES-256-GCM |
| Admin Console | `weak-passwd` | A02 Cryptographic Failures | Weak Password Storage: plaintext in response → unsalted MD5 → bcrypt |
| Account Login | `brute-force` | A04 Insecure Design | Brute Force: no limits → 10-attempt / 30s lock → exponential back-off |
| Forgot Password | `pwd-reset` | A04 Insecure Design | Insecure Password Reset: unlimited guesses → weak rate limit → proper lock-out |
| System Status | `debug-info` | A05 Security Misconfiguration | Info Disclosure: full env vars + stack trace → partial → safe generic errors |
| Security Check | `security-headers` | A05 Security Misconfiguration | Missing Headers: none → minimal → full CSP / HSTS / X-Frame-Options |

### Difficulty levels

| Level | Behaviour |
|---|---|
| **Easy** | Textbook vulnerability, no mitigations |
| **Medium** | Weak mitigation that can be bypassed |
| **Hard** | Secure implementation (reference solution) |

Switch difficulty at any time from the **Security** page — it takes effect immediately for all modules.

### Hint system

Each module has four progressive hints. On a module page click **Show Hint (1/4)** and keep clicking to reveal more detail.  
Hints range from a gentle nudge ("How are your notes protected at rest?") to near-complete guidance ("Base64 decode the values to reveal plaintext").

---

## Getting Started

### Docker (recommended)

```bash
git clone https://github.com/minhthetroller/DVGA.git
cd DVGA
docker compose up --build
```

Open [http://localhost:4280](http://localhost:4280).  
The SQLite database is persisted in a named Docker volume (`dvga-data`).

### Go directly

Requires Go 1.25+ and a C compiler (SQLite uses CGO).

```bash
git clone https://github.com/minhthetroller/DVGA.git
cd DVGA
go run ./cmd/dvga
```

Open [http://localhost:4280](http://localhost:4280).

---

## Usage

1. **Log in** — default credentials are `admin / admin`.
2. **Pick a module** from the sidebar on the home page.
3. **Start on Easy** and try to exploit the vulnerability.
4. Use the **hint button** if you get stuck.
5. Switch to **Hard** to see the secure implementation and compare.
6. Use **Setup** → Reset Database to restore the default seeded data at any time.

### Default accounts

| Username | Password | Role |
|---|---|---|
| admin | admin | admin |
| gordonb | abc123 | user |
| pablo | letmein | user |
| 1337 | charley | user |

---

## Architecture

```
Request
  └─ chi Router
       └─ Auth middleware (session cookie)
            └─ Handler
                 └─ Registry.Build(moduleID, difficulty)
                       └─ Factory.Create(difficulty)  →  VulnModule
                            └─ Chain.Apply() [Logger + Difficulty decorators]
                                 └─ Module.ServeHTTP()
```

### Key components

| Package | Responsibility |
|---|---|
| `cmd/dvga` | Entry point, signal handling, graceful shutdown |
| `internal/app` | App wiring — DB, sessions, registry, server startup |
| `internal/core` | `VulnModule` interface, `Registry`, `Chain`, `SafeDifficulty` |
| `internal/ui` | HTTP handlers, template renderer, hint API |
| `internal/middleware` | Logger and difficulty decorator implementations |
| `internal/modules/*` | One package per OWASP category, module factories + handlers |
| `internal/database` | GORM models, auto-migrate, seed data |
| `internal/session` | In-memory session store with TTL cleanup goroutine |

### Routes

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/login` | Login form |
| `GET` | `/logout` | Destroy session |
| `GET` | `/` | Home — module sidebar |
| `GET/POST` | `/security` | Difficulty selector |
| `GET/POST` | `/setup` | Database reset |
| `GET` | `/about` | About page |
| `GET/POST` | `/vulnerabilities/{id}` | Module page |
| `GET` | `/vulnerabilities/{id}/hint?level=1` | Progressive hint (1–4) |
| `GET` | `/static/*` | CSS / static assets |

---

## Database

SQLite file at `./data/dvga.db` (auto-created on first run).

### Models

| Table | Purpose |
|---|---|
| `users` | Accounts — username, password (plaintext for demo), role, secret Q&A |
| `secrets` | Per-user sensitive notes (used by IDOR and Crypto modules) |
| `comments` | Guestbook entries (used by Stored XSS module) |
| `reset_tokens` | Single-use password reset tokens with expiry timestamps |

---

## Configuration

All configuration is hardcoded for simplicity.

| Setting | Value |
|---|---|
| Listen address | `:4280` |
| Database path | `./data/dvga.db` |
| Read timeout | 15 s |
| Write timeout | 30 s |
| Idle timeout | 60 s |
| Graceful shutdown timeout | 10 s |
| Session TTL | 30 min |
| Rate-limit tracker TTL | 1 hr |
| Cleanup interval | 5 min |

---

## Development

```bash
# Run tests
go test ./...

# Build binary
go build -o dvga ./cmd/dvga

# Rebuild Docker image
docker compose up --build
```

**Dependencies**: chi, zerolog, httplog, GORM, go-sqlite3, golang.org/x/crypto.

See [go.mod](go.mod) for the full dependency list.

