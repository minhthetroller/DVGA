# DVGA — Deliberately Vulnerable Go Application

A purposely insecure web application for learning and practising web security concepts.  

DVGA includes:
- 5 OWASP Top 10 (2021) web security categories (A01 to A05)
- 5 OWASP API Security Top 10 (2023) vulnerabilities (API1 to API5)
- Easy, Medium, and Hard difficulty modes
- A 4-level progressive hint system

> **Warning — for educational use only. Never deploy this application on a public or production network.**

---

## Table of Contents

- [Features](#features)
- [Vulnerability Coverage](#vulnerability-coverage)
     - [Web Modules (OWASP Top 10 2021: A01-A05)](#web-modules-owasp-top-10-2021-a01-a05)
     - [API Modules (OWASP API Security 2023: API1–API5)](#api-modules-owasp-api-security-2023-api1-api5)
- [Difficulty Levels](#difficulty-levels)
- [Hint System](#hint-system)
- [Getting Started](#getting-started)
     - [Docker (recommended)](#docker-recommended)
     - [Go directly](#go-directly)
- [Usage](#usage)
- [Architecture](#architecture)
     - [Request Flow](#request-flow)
     - [Key Components](#key-components)
     - [Module Registration](#module-registration)
- [Routes](#routes)
     - [UI Routes](#ui-routes)
     - [API Routes](#api-routes)
- [Database](#database)
- [Configuration](#configuration)
- [Development](#development)

---

## Features

- 27 vulnerability modules across web and API contexts
- Coverage of 10 security categories total:
     - 5 OWASP Top 10 (2021) web categories (A01 to A05)
     - 5 OWASP API Security (2023) vulnerabilities (API1 to API5)
- Per-module **Easy → Medium → Hard** difficulty progression
- **4-level progressive hints** revealed on demand (no spoilers unless you ask)
- Realistic-looking UI — vulnerabilities are disguised as normal application features
- SQLite database, no external services required
- Docker Compose for zero-config setup

---

## Vulnerability Coverage

### Web Modules (OWASP Top 10 2021: A01-A05)

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

### API Modules (OWASP API Security 2023: API1–API5)

| API ID | Vulnerability | Scenario modules | Example endpoints |
|---|---|---|---|
| API1 | Broken Object Level Authorization | `member-profile`, `order-tracker`, `document-fetch` | `GET /api/v1/members/{id}`, `GET /api/v1/orders/{id}`, `GET /api/v1/documents/{id}` |
| API2 | Broken Authentication | `mobile-login`, `session-renewal` | `POST /api/v1/auth/token`, `POST /api/v1/auth/refresh` |
| API3 | Broken Object Property Level Authorization | `profile-setting`, `order-details`, `invoice-adjuster` | `PATCH /api/v1/members/me`, `GET /api/v1/orders/{id}/details`, `PATCH /api/v1/invoices/{id}` |
| API4 | Unrestricted Resource Consumption | `report-generator`, `notification-blast` | `POST /api/v1/reports/generate`, `POST /api/v1/notifications/send` |
| API5 | Broken Function Level Authorization | `user-status-toggle`, `support-tools`, `refund-processor` | `POST /api/v1/members/{id}/suspend`, `GET /api/v1/admin/dashboard`, `POST /api/v1/orders/{id}/refund` |

## Difficulty levels

| Level | Behaviour |
|---|---|
| **Easy** | Textbook vulnerability with minimal or no mitigation |
| **Medium** | Partial or weak mitigation that can still be bypassed |
| **Hard** | Secure implementation (reference baseline) |

You can switch difficulty from the **Security** page. The selected difficulty applies globally to all modules.

## Hint system

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

### Request Flow

```
Request
  └─ chi Router
       └─ Auth middleware (session cookie)
            └─ UI Handler
                 └─ Registry.Build(moduleID, difficulty)
                       └─ Factory.Create(difficulty) returns module instance
                            └─ Chain.Apply(module) wraps decorators
                                 └─ Module.ServeHTTP()
```

### Key components

| Package | Responsibility |
|---|---|
| `cmd/dvga` | Entry point, startup, graceful shutdown |
| `internal/app` | Application wiring: DB, session manager, registry, HTTP server |
| `internal/core` | `VulnModule` interface, `Registry`, `ModuleConstructor`, `Chain`, `SafeDifficulty` |
| `internal/ui` | HTTP handlers, templates, hint endpoint |
| `internal/middleware` | Logger and difficulty decorator implementations |
| `internal/modules/*` | One package per OWASP category, module factories + handlers |
| `internal/database` | Models, migration, seed/reset workflows |
| `internal/session` | In-memory session store with TTL cleanup |

### Module Registration

Each category registers module constructors through RegisterAll functions.
At runtime, the registry resolves module ID + difficulty to build an instance, then the decorator chain is applied before request handling.

This design replaces a factory-heavy approach with a lighter registry + constructor pattern while preserving decorator-based cross-cutting behavior.

## Routes

### UI Routes

| Method | Path | Description |
|---|---|---|
| `GET/POST` | `/login` | Login page and authentication |
| `GET` | `/logout` | Session termination |
| `GET` | `/` | Home page and module list |
| `GET/POST` | `/security` | Global difficulty selector |
| `GET/POST` | `/setup` | Database reset utilities |
| `GET` | `/about` | Project overview |
| `GET/POST` | `/vulnerabilities/{id}` | Module page |
| `GET` | `/vulnerabilities/{id}/hint?level=1..4` | Progressive hint retrieval |
| `GET` | `/static/*` | Static assets |

### API Routes (API1–API5 scenarios)

| Method | Path | API Category |
|---|---|---|
| `GET` | `/api/v1/members/{id}` | API1 |
| `GET` | `/api/v1/orders/{id}` | API1 |
| `GET` | `/api/v1/documents/{id}` | API1 |
| `POST` | `/api/v1/auth/token` | API2 |
| `POST` | `/api/v1/auth/refresh` | API2 |
| `PATCH` | `/api/v1/members/me` | API3 |
| `GET` | `/api/v1/orders/{id}/details` | API3 |
| `PATCH` | `/api/v1/invoices/{id}` | API3 |
| `POST` | `/api/v1/reports/generate` | API4 |
| `POST` | `/api/v1/notifications/send` | API4 |
| `POST` | `/api/v1/members/{id}/suspend` | API5 |
| `GET` | `/api/v1/admin/dashboard` | API5 |
| `POST` | `/api/v1/orders/{id}/refund` | API5 |

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

Configuration is intentionally simple and mostly fixed for learning consistency.

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

Common commands:

```bash
# Run tests
go test ./...

# Build binary
go build -o dvga ./cmd/dvga

# Rebuild Docker image
docker compose up --build
```

**Main dependencies** include chi, zerolog, httplog, GORM, go-sqlite3, golang.org/x/crypto.

See [go.mod](go.mod) for the full dependency list.