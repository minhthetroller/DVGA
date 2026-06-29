# DVGA Apex HTTPS + Staged Launch Progress Bar — Design

Date: 2026-06-30
Status: Approved

## Problem

1. **Apex HTTPS untrusted in browser.** `https://dvga.online` shows a
   "Not Secure" / cert error in the user's browser while per-user
   subdomains (`https://<user>.dvga.online`) display a valid Let's Encrypt
   lock. Server-side inspection shows the apex cert is in fact valid
   (`*.dvga.online` with SAN `dvga.online`, full LE chain, system CA
   verifies OK). The browser had seen Traefik's self-signed default cert
   during earlier broken deploys and pinned the error; a stale leftover
   standalone `dvga.online` cert in `acme.json` adds cert-selection
   ambiguity.
2. **No launch feedback.** `POST /signup` is synchronous: the provisioner
   blocks for ~45-60s while `RunTask -> WaitForRunning -> GetTaskIP ->
   dynamic.Add` complete, then redirects. The user sees a frozen form
   with no indication that a Fargate task is being provisioned.

## Goals

- Apex `dvga.online` shows a valid Let's Encrypt lock in the browser,
  same as subdomains.
- Users see a real, ECS-lifecycle-driven progress bar when launching a
  Fargate instance, then get redirected to their subdomain.

## Non-goals

- Persistent session store (out of scope; separate follow-up).
- Auth/CSRF on the launch-status poll (username is the only handle,
  low risk on a deliberately-vulnerable training app).
- Default-certificate overrides beyond the wildcard ACME cert.

## Part A - Apex HTTPS

### Root cause

- Earlier deploys served Traefik's self-signed `TRAEFIK DEFAULT CERT`
  because the LE Route53 DNS-01 challenge was failing. The user's
  browser recorded a cert error / possible HSTS state for the apex.
- `acme.json` currently contains two LE certs: a stale standalone
  `dvga.online` (issued before `tls.domains` was configured) and the
  wildcard `*.dvga.online` (+ SAN `dvga.online`). Traefik serves the
  wildcard for the apex today (verified), but the stale cert creates
  ambiguity and persists a redundant cert.

### Fix (operational, one-time)

1. SSH to the EC2 host, stop Traefik, delete `/opt/dvga/acme.json`,
   restart Traefik.
2. Traefik re-issues only the wildcard cert, because the current config
   (`provisioner` router has `tls.domains[0].main=*.dvga.online` +
   `sans=dvga.online`) requests only that cert - per Traefik docs, when
  `tls.domains` is set the resolver ignores `Host()` matchers.
3. Verify apex + subdomain both serve the wildcard LE cert with full
   chain (`openssl s_client`, `curl --cacert`, SAN check).
4. User hard-refreshes / opens `https://dvga.online` in incognito;
   if still flagged, clear HSTS for `dvga.online`.

### No code/infra change

The Terraform/Ansible/Traefik config is already correct; Part A is a
one-time state cleanup, not a committed change.

## Part B - Staged launch progress bar

### Architecture

```
Browser                  Provisioner (Go)              AWS ECS
  |  POST /signup ----->  validate                      |
  |                       create LaunchState(submitting)|
  |  <--- 202 + page ---   spawn goroutine -----------> RunTask
  |  poll /launch/{u}     goroutine: poll DescribeTasks (provisioning -> starting)
  |  <-- {percent,stage}  GetTaskIP (routing)
  |  <-- {percent,stage}  dynamic.Add + sessions.Add (ready)
  |  window.location = https://<user>.<domain>
```

### Components

**`provisioner/launch.go` (new)**
- `type Stage string` - `"submitting" | "provisioning" | "starting" | "routing" | "ready" | "failed"`.
- `type LaunchState struct { Stage; Percent int; Message string; Error string }`.
- `type LaunchTracker struct { mu sync.RWMutex; states map[string]LaunchState }`.
- Methods: `Set(username, state)`, `Get(username) (LaunchState, bool)`, `Delete(username)`.
- No TTL removal in v1; the goroutine `Delete`s on terminal `ready`/`failed`. Orphan
  entries from client disconnect are acceptable for v1 (follow-up: expiry GC).

**`provisioner/ecs.go`**
- Add `RunTaskProgress(taskArn, tracker, username) error`:
  - loops `DescribeTask` every 2s up to 60s;
  - sets `provisioning` (30%) when `LastStatus in {PROVISIONING, PENDING}`;
  - sets `provisioning`(45%) on pending-running transitions;
  - sets `starting` (60%) when `LastStatus == RUNNING`;
  - returns once RUNNING. On timeout, sets `failed`.
- Keep existing `WaitForRunning`/`StopTask`/`GetTaskIP`.

**`provisioner/handlers.go`**
- `Handlers` gains a `tracker *LaunchTracker`.
- `signup`:
  1. validate username (existing regex), reject duplicates / max users
     (returns the form with error - no progress bar).
  2. `tracker.Set(username, {submitting, 10, "Submitting request..."})`.
  3. `go h.launchInstance(username)` - runs `RunTask` -> on error
     `tracker.Set failed` + log; on success `RunTaskProgress` ->
     `GetTaskIP` (`routing` 85%) -> `dynamic.Add` + `sessions.Add`
     (`ready` 100%).
  4. Render `signup.html` in "launching" mode with the username and
     return HTTP 202.
- New handler `launchStatus(w, r)`: `username := r.PathValue("username")`;
  `tracker.Get` -> JSON `{stage, percent, message, error}`; 404 if absent.
- Register `GET /launch/{username}` in `main.go`.

**`provisioner/main.go`**
- Create `tracker := NewLaunchTracker()`; pass to `NewHandlers` and the
  inactivity monitor unchanged.

**`provisioner/templates/signup.html`**
- Add `{{if .Launching}}...{{else}}<form>...{{end}}`.
- Launching section: heading "Launching your instance", a
  `<div class="progress"><div id="bar"></div></div>`, a stage label
  `<p id="stage">`, the username embedded for the JS.
- JS (inline, no external deps; matches GitHub-dark theme):
  - constants `username`, `domain` from the template.
  - `poll()` every 1500ms: `fetch('/launch/'+username)`, update
    `#bar.style.width` and `#stage.textContent`.
  - on `stage == "ready"`: set bar 100%, "Redirecting...",
    `window.location = 'https://'+username+'.'+domain`.
  - on `stage == "failed"`: show the error in the `.error` block and
    re-show the form.

### Stages table

| Stage        | Percent | Trigger                              |
|--------------|---------|--------------------------------------|
| submitting   | 10      | handler accepted form                |
| provisioning | 30-45   | task `PROVISIONING`/`PENDING`        |
| starting     | 60      | task `RUNNING`                       |
| routing      | 85      | `GetTaskIP` resolved ENI             |
| ready        | 100     | `dynamic.Add` + `sessions.Add`       |
| failed       | -       | any error; message shown, form re-shows |

### Error handling

- Duplicate username / max users / invalid username: synchronous form
  re-render with `.Error` (unchanged behavior; no bar).
- `RunTask` failure (e.g., `InvalidParameterException`): `failed`,
  message from the AWS error, `StopTask` not called (no task).
- `RunTaskProgress` timeout: `failed` with "Instance launch timed
  out", `StopTask` called.
- `GetTaskIP` failure: `failed`, `StopTask` called.
- Client disconnects mid-poll: tracker entry remains until terminal
  (goroutine continues; entry not deleted). v1 acceptable.

### Testing

- `go vet ./...` and `go build ./...` in `provisioner/`.
- Manual: `curl -X POST -d username=foo https://dvga.online/signup`
  returns 202 with launching section; `curl
  https://dvga.online/launch/foo` shows stage progression; browser
  shows bar advancing then redirects to working `https://foo.dvga.online`.
- CI: `deploy.yml` unchanged; push to main triggers build + push
  provisioner image + Ansible redeploy.

## Deploy sequence

1. Implement Part B edits.
2. `go vet` / `go build`; commit + push to `main`.
3. GitHub Actions `deploy.yml` runs (terraform apply, build & push
   images, Ansible deploy).
4. After Ansible success: SSH to EC2 host, `docker compose stop traefik`,
   `sudo rm /opt/dvga/acme.json`, `docker compose start traefik`; wait
   for wildcard cert re-issue.
5. Verify apex + subdomain serve wildcard LE cert; verify progress bar
   end-to-end in a browser.
6. Ask user to hard-refresh / incognito `https://dvga.online`.

## Out of scope / follow-ups

- Persistent session store (reconcile from `ListTasks` + `username` tag
  on provisioner restart) - separate task.
- TTL cleanup for `LaunchTracker` orphan entries.
- Default-TLS-certificate hardening (serve the wildcard as the entrypoint
  default to fully eliminate selection ambiguity) - deferred; the
  wildcard-only `acme.json` after the cleanup achieves the same effect.

## Risks

- Provisioner restart mid-launch orphans the goroutine; tracker entry
  stays non-terminal. v1 acceptable (training app, low traffic).
- Polling endpoint is unauthenticated; a user could read another user's
  launch stage. Low risk on a deliberately vulnerable training app.
- Browser HSTS pinning may require manual clearing
  (`chrome://net-internals/#hsts`) if incognito doesn't clear the error.