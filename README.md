# C23 Forge PTY Gateway

WebSocket PTY gateway for C23 Forge learner environments.

## Deployment

1. Push this repository to GitHub.
2. In Render, create or update the `c23-forge-pty-gateway` Web Service.
3. Render should use:
   - Build command: `npm install`
   - Start command: `npm start`
   - Health check path: `/health`
4. Set required Render environment variables:
   - `E2B_API_KEY`
   - `TERMINAL_TOKEN_SECRET`
   - `ALLOWED_ORIGINS`
5. Optional but recommended for production durability:
   - `REDIS_URL`
6. Set the Base44 terminal gateway URL to:
   - `wss://<render-service-host>/terminal`

## Architecture

The gateway implements learner-environment lifecycle management.

Default behavior:

- One default learner environment per authenticated user.
- Browser terminal windows attach to that environment.
- Browser refresh, route remount, websocket reconnect, and short disconnect do not create a fresh sandbox.
- Manual reset intentionally destroys/recreates the learner environment.
- Content may request a fresh/named isolated environment by passing an explicit `environmentMode` and `environmentKey`.

The browser terminal is only a client attachment. The E2B sandbox and PTY are the learner environment.

## Primary WebSocket protocol: environment-v1

Endpoint:

```text
wss://<host>/terminal
```

### Attach / get-or-create

Base44 should send this when a terminal-bearing page loads:

```json
{
  "type": "attach",
  "token": "<signed JWT>",
  "environmentMode": "user_default_environment",
  "environmentKey": "default:user:<stable-user-id>",
  "templateId": "base",
  "cols": 80,
  "rows": 24,
  "diagnosticId": "diag_optional"
}
```

If `environmentKey` is omitted, the gateway derives:

```text
default:user:<token user id>
```

The JWT must include at least one stable user identity claim:

- `userId`
- `user_id`
- `sub`
- `email`
- `email_address`
- `uid`

Recommended JWT claims:

```json
{
  "userId": "<stable-user-id>",
  "environmentKey": "default:user:<stable-user-id>",
  "exp": 9999999999
}
```

### Ready response

```json
{
  "type": "ready",
  "protocol": "environment-v1",
  "environmentId": "...",
  "environmentKey": "default:user:<stable-user-id>",
  "environmentMode": "user_default_environment",
  "gatewaySessionId": "...",
  "sandboxId": "...",
  "pid": 123,
  "ptyPid": 123,
  "resumed": true,
  "created": false,
  "reset": false
}
```

Base44 should persist the returned `environment`, `sandboxId`, `ptyPid`, and `gatewaySessionId` to its `TerminalSession` record.

### Attach after gateway restart

If Redis is not configured or the gateway restarted, Base44 can still let the gateway adopt known sandbox metadata:

```json
{
  "type": "attach",
  "token": "<signed JWT>",
  "environmentMode": "user_default_environment",
  "environmentKey": "default:user:<stable-user-id>",
  "sandboxId": "<previous sandbox id>",
  "ptyPid": 123,
  "cols": 80,
  "rows": 24
}
```

The gateway will validate the environment key, adopt the provided IDs, and reconnect if E2B still has the sandbox and PTY.

### Input

```json
{
  "type": "input",
  "data": "ls -la\r"
}
```

### Resize

```json
{
  "type": "resize",
  "cols": 120,
  "rows": 36
}
```

### Reset environment

Use only for intentional destructive reset:

```json
{
  "type": "reset",
  "token": "<signed JWT>",
  "environmentMode": "user_default_environment",
  "environmentKey": "default:user:<stable-user-id>",
  "cols": 80,
  "rows": 24
}
```

### Idle warning

After the attached idle warning threshold, the gateway sends:

```json
{
  "type": "idle_warning",
  "code": "ARE_YOU_STILL_THERE",
  "message": "Are you still using this terminal and lesson?",
  "expiresInMs": 600000
}
```

Base44 should show a confirmation dialog. If the learner clicks yes, send:

```json
{
  "type": "idle_confirm",
  "diagnosticId": "diag_optional"
}
```

### Expired

If the learner does not confirm activity after the warning grace window:

```json
{
  "type": "expired",
  "code": "ATTACHED_IDLE_TIMEOUT",
  "message": "Terminal environment expired after extended inactivity."
}
```

## Content environment modes

Default:

```json
{
  "environmentMode": "user_default_environment"
}
```

Fresh content-specific environment:

```json
{
  "environmentMode": "fresh_isolated_environment",
  "environmentKey": "content:<content-id>:user:<stable-user-id>:generation:0"
}
```

Named content-specific environment:

```json
{
  "environmentMode": "named_isolated_environment",
  "environmentKey": "named:<profile-or-lab-key>:user:<stable-user-id>"
}
```

## Legacy compatibility

The gateway still supports older messages:

- `start`
- `resume`
- `reconnect`
- `kill`

By default, `start` is upgraded to environment get-or-create when the JWT contains a stable user identity. Set `ENABLE_LEGACY_START_CREATES_NEW=true` only if you need the old destructive behavior temporarily.

## Persistence notes

Without `REDIS_URL`, the environment registry is stored in the Render process memory. This is enough for browser refreshes and normal reconnects while the Render process remains alive.

For cleaner production behavior across Render restarts, set `REDIS_URL`. Even without Redis, Base44 should persist `sandboxId` and `ptyPid` so the gateway can adopt and reconnect to the existing E2B environment after restart.

## Health check

```text
GET /health
```

Returns active runtime handles, environment record counts, lifecycle settings, and whether Redis is configured.

## Status endpoint

```text
GET /environments/status?token=<jwt>&environmentKey=<key>
```

Prefer using the WebSocket `attach` flow for normal application behavior. The status endpoint is primarily for diagnostics.
