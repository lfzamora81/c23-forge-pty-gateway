import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Sandbox } from 'e2b';
import dotenv from 'dotenv';
import cors from 'cors';
import Redis from 'ioredis';

dotenv.config();

const WS_OPEN = 1;

const parseMs = (value, fallback) => {
  const parsed = Number.parseInt(value || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const parseBool = (value, fallback = false) => {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
};

const PORT = process.env.PORT || 10000;
const E2B_API_KEY = process.env.E2B_API_KEY;
const TERMINAL_TOKEN_SECRET = process.env.TERMINAL_TOKEN_SECRET;
const REDIS_URL = process.env.REDIS_URL || '';

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const ALLOWED_ORIGIN_SUFFIXES = (process.env.ALLOWED_ORIGIN_SUFFIXES || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
  .map((s) => (s.startsWith('.') ? s : `.${s}`));

const DEFAULT_TEMPLATE_ID = process.env.DEFAULT_TEMPLATE_ID || 'base';

// Learner-environment lifecycle policy.
const DETACHED_GRACE_MS = parseMs(process.env.DETACHED_GRACE_MS || process.env.SESSION_GRACE_MS, 15 * 60 * 1000);
const DETACHED_EXPIRE_MS = parseMs(process.env.DETACHED_EXPIRE_MS, 60 * 60 * 1000);
const ATTACHED_IDLE_WARNING_MS = parseMs(process.env.ATTACHED_IDLE_WARNING_MS, 4 * 60 * 60 * 1000);
const ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS = parseMs(
  process.env.ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS,
  10 * 60 * 1000
);
const PRODUCT_ATTACHED_IDLE_LIFETIME_MS = ATTACHED_IDLE_WARNING_MS + ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS;

// E2B sandbox keepalive timeout. Clamp it so an old Render env var cannot undercut the product policy.
const RAW_TERMINAL_IDLE_TIMEOUT_MS = parseMs(
  process.env.TERMINAL_IDLE_TIMEOUT_MS ||
    process.env.SANDBOX_TIMEOUT_MS ||
    process.env.IDLE_TIMEOUT_MS,
  PRODUCT_ATTACHED_IDLE_LIFETIME_MS
);
const TERMINAL_IDLE_TIMEOUT_MS = Math.max(RAW_TERMINAL_IDLE_TIMEOUT_MS, PRODUCT_ATTACHED_IDLE_LIFETIME_MS);

const START_TIMEOUT_MS = parseMs(process.env.START_TIMEOUT_MS, 90 * 1000);
const PROTOCOL_HEARTBEAT_MS = parseMs(process.env.PROTOCOL_HEARTBEAT_MS, 30 * 1000);
const ENVIRONMENT_RECORD_TTL_MS = parseMs(process.env.ENVIRONMENT_RECORD_TTL_MS, 24 * 60 * 60 * 1000);
const ENVIRONMENT_SWEEP_MS = parseMs(process.env.ENVIRONMENT_SWEEP_MS, 60 * 1000);
const TIMEOUT_REFRESH_THROTTLE_MS = parseMs(process.env.TIMEOUT_REFRESH_THROTTLE_MS, 60 * 1000);
const STALE_ATTACHED_RECREATE_MS = parseMs(
  process.env.STALE_ATTACHED_RECREATE_MS || process.env.STALE_ATTACHED_RECORD_MS,
  TERMINAL_IDLE_TIMEOUT_MS + 60 * 1000
);
const REDIS_CONNECT_TIMEOUT_MS = parseMs(process.env.REDIS_CONNECT_TIMEOUT_MS, 5 * 1000);
const REDIS_COMMAND_TIMEOUT_MS = parseMs(process.env.REDIS_COMMAND_TIMEOUT_MS, 5 * 1000);
const ENABLE_LEGACY_START_CREATES_NEW = parseBool(process.env.ENABLE_LEGACY_START_CREATES_NEW, false);
const REFRESH_SANDBOX_TIMEOUT_ON_PING = parseBool(process.env.REFRESH_SANDBOX_TIMEOUT_ON_PING, true);

if (!E2B_API_KEY) throw new Error('E2B_API_KEY required');
if (!TERMINAL_TOKEN_SECRET) throw new Error('TERMINAL_TOKEN_SECRET required');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/terminal' });

app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error(`Origin not allowed: ${origin}`));
    },
  })
);

app.use(express.json());

const redis = REDIS_URL
  ? new Redis(REDIS_URL, {
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
      enableOfflineQueue: false,
      lazyConnect: true,
      connectTimeout: REDIS_CONNECT_TIMEOUT_MS,
      commandTimeout: REDIS_COMMAND_TIMEOUT_MS,
    })
  : null;

if (redis) {
  redis.on('error', (error) => {
    console.error('[redis] error', safePublicError(error));
  });

  redis
    .connect()
    .then(() => console.log('[redis] connected'))
    .catch((error) => console.error('[redis] initial connect failed; memory fallback active', safePublicError(error)));
}

class EnvironmentStore {
  constructor(redisClient) {
    this.redis = redisClient;
    this.memory = new Map();
    this.prefix = 'c23forge:environment:';
    this.lastRedisErrorAt = null;
  }

  key(environmentKey) {
    return `${this.prefix}${environmentKey}`;
  }

  noteRedisError(operation, error) {
    this.lastRedisErrorAt = Date.now();
    console.warn(`[environment-store] redis ${operation} failed; using memory fallback`, safePublicError(error));
  }

  serialize(record) {
    return JSON.stringify({
      environmentId: record.environmentId,
      environmentKey: record.environmentKey,
      environmentMode: record.environmentMode,
      userId: record.userId,
      sandboxId: record.sandboxId,
      ptyPid: record.ptyPid,
      templateId: record.templateId,
      status: record.status,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      lastActiveAt: record.lastActiveAt,
      lastAttachedAt: record.lastAttachedAt,
      lastDetachedAt: record.lastDetachedAt,
      lastKeepAliveAt: record.lastKeepAliveAt || null,
      expiresAt: record.expiresAt,
      resetGeneration: record.resetGeneration || 0,
      diagnosticId: record.diagnosticId || 'no-diagnostic-id',
      adoptedFromClient: Boolean(record.adoptedFromClient),
      lastError: record.lastError || null,
      staleReason: record.staleReason || null,
    });
  }

  deserialize(raw) {
    if (!raw) return null;
    if (typeof raw === 'object') return { ...raw };

    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async get(environmentKey) {
    if (!environmentKey) return null;

    if (this.redis) {
      try {
        const raw = await this.redis.get(this.key(environmentKey));
        const redisRecord = this.deserialize(raw);
        if (redisRecord) return redisRecord;
      } catch (error) {
        this.noteRedisError('get', error);
      }
    }

    return this.deserialize(this.memory.get(environmentKey));
  }

  async set(record) {
    if (!record?.environmentKey) return;

    const serialized = this.serialize({
      ...record,
      updatedAt: Date.now(),
    });

    this.memory.set(record.environmentKey, serialized);

    if (this.redis) {
      try {
        await this.redis.set(this.key(record.environmentKey), serialized, 'PX', ENVIRONMENT_RECORD_TTL_MS);
      } catch (error) {
        this.noteRedisError('set', error);
      }
    }
  }

  async delete(environmentKey) {
    if (!environmentKey) return;

    this.memory.delete(environmentKey);

    if (this.redis) {
      try {
        await this.redis.del(this.key(environmentKey));
      } catch (error) {
        this.noteRedisError('delete', error);
      }
    }
  }

  async list() {
    const byKey = new Map();

    for (const [environmentKey, raw] of this.memory.entries()) {
      const record = this.deserialize(raw);
      if (record) byKey.set(environmentKey, record);
    }

    if (!this.redis) return Array.from(byKey.values());

    try {
      let cursor = '0';

      do {
        const [nextCursor, keys] = await this.redis.scan(cursor, 'MATCH', `${this.prefix}*`, 'COUNT', 100);
        cursor = nextCursor;

        if (keys.length > 0) {
          const values = await this.redis.mget(keys);
          values
            .map((raw) => this.deserialize(raw))
            .filter(Boolean)
            .forEach((record) => byKey.set(record.environmentKey, record));
        }
      } while (cursor !== '0');
    } catch (error) {
      this.noteRedisError('list', error);
    }

    return Array.from(byKey.values());
  }
}

const environmentStore = new EnvironmentStore(redis);

// Runtime handles are intentionally process-local. Durable metadata lives in EnvironmentStore.
const runtimeHandles = new Map();
const legacySessions = new Map();

function safePublicError(error) {
  const message = error?.message || String(error || 'Unknown gateway error');
  return message.replace(E2B_API_KEY || 'NO_API_KEY', '[redacted]');
}

function withTimeout(promise, ms, label) {
  let timer;

  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
  });

  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function isAllowedOrigin(origin) {
  if (!origin) return true;

  if (ALLOWED_ORIGINS.includes(origin)) {
    return true;
  }

  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }

  const protocol = parsed.protocol;
  const hostname = parsed.hostname.toLowerCase();

  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';

  if (protocol !== 'https:' && !(protocol === 'http:' && isLocalhost)) {
    return false;
  }

  return ALLOWED_ORIGIN_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function parseJsonMessage(data) {
  try {
    return JSON.parse(data.toString());
  } catch {
    return null;
  }
}

function normalizePid(value) {
  const pid = Number(value);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

function verifyTerminalToken(token) {
  if (!token) throw new Error('Terminal token is required.');
  return jwt.verify(token, TERMINAL_TOKEN_SECRET, { algorithms: ['HS256'] });
}

function getTemplateId(msg) {
  return msg.template || msg.templateId || DEFAULT_TEMPLATE_ID;
}

function getDiagnosticId(msg) {
  return msg?.diagnosticId || msg?.diagnostic_id || 'no-diagnostic-id';
}

function logWithDiag(diagnosticId, message, data = undefined) {
  if (data === undefined) {
    console.log(`[${diagnosticId}] ${message}`);
    return;
  }

  console.log(`[${diagnosticId}] ${message}`, data);
}

function warnWithDiag(diagnosticId, message, data = undefined) {
  if (data === undefined) {
    console.warn(`[${diagnosticId}] ${message}`);
    return;
  }

  console.warn(`[${diagnosticId}] ${message}`, data);
}

function errorWithDiag(diagnosticId, message, data = undefined) {
  if (data === undefined) {
    console.error(`[${diagnosticId}] ${message}`);
    return;
  }

  console.error(`[${diagnosticId}] ${message}`, data);
}

function sendWsMessage(ws, msg) {
  if (ws.readyState !== WS_OPEN) return false;
  ws.send(JSON.stringify(msg));
  return true;
}

function sendWsError(ws, diagnosticId, code, message, extra = {}) {
  errorWithDiag(diagnosticId, `[gateway error] ${code}: ${message}`);
  sendWsMessage(ws, {
    type: 'error',
    code,
    message,
    diagnosticId,
    ...extra,
  });
}

function safeKeyPart(value) {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9_.:@-]/g, '_');
}

function extractUserId(payload) {
  return (
    payload?.userId ||
    payload?.user_id ||
    payload?.sub ||
    payload?.email ||
    payload?.email_address ||
    payload?.uid ||
    null
  );
}

function normalizeEnvironmentMode(value) {
  const mode = value || 'user_default_environment';
  const allowed = new Set([
    'user_default_environment',
    'fresh_isolated_environment',
    'named_isolated_environment',
  ]);

  return allowed.has(mode) ? mode : 'user_default_environment';
}

function defaultEnvironmentKeyForUser(userId) {
  return `default:user:${safeKeyPart(userId)}`;
}

function contentEnvironmentKeyForUser(userId, msg) {
  const contentId = msg.contentId || msg.content_id || msg.lessonId || msg.lesson_id || msg.projectId || msg.project_id;
  const generation = msg.generation || msg.resetGeneration || 0;

  if (!contentId) return defaultEnvironmentKeyForUser(userId);
  return `content:${safeKeyPart(contentId)}:user:${safeKeyPart(userId)}:generation:${safeKeyPart(generation)}`;
}

function resolveEnvironmentRequest(msg, payload) {
  const userId = extractUserId(payload);
  if (!userId) {
    throw new Error('Terminal token must include a stable userId, user_id, sub, or email claim for learner-environment attach/reset.');
  }

  const environmentMode = normalizeEnvironmentMode(
    msg.environmentMode || msg.environment_mode || payload.environmentMode || payload.environment_mode
  );

  let environmentKey = msg.environmentKey || msg.environment_key || payload.environmentKey || payload.environment_key;

  if (!environmentKey) {
    environmentKey = environmentMode === 'user_default_environment'
      ? defaultEnvironmentKeyForUser(userId)
      : contentEnvironmentKeyForUser(userId, msg);
  }

  const safeUserId = safeKeyPart(userId);
  const defaultKey = defaultEnvironmentKeyForUser(userId);

  const tokenEnvironmentKey = payload.environmentKey || payload.environment_key;
  if (tokenEnvironmentKey && tokenEnvironmentKey !== environmentKey) {
    throw new Error('Token environmentKey does not match requested environmentKey.');
  }

  const userScoped = environmentKey === defaultKey || environmentKey.includes(`user:${safeUserId}`);
  if (!tokenEnvironmentKey && !userScoped) {
    throw new Error('Requested environmentKey is not scoped to the authenticated user.');
  }

  return {
    userId: String(userId),
    environmentKey,
    environmentMode,
    templateId: getTemplateId(msg),
  };
}

function validateResumeClaims(payload, sandboxId, ptyPid) {
  if (payload?.sandboxId && payload.sandboxId !== sandboxId) {
    throw new Error('Token sandboxId does not match requested sandboxId.');
  }

  const tokenPid = payload?.ptyPid || payload?.pid;
  if (tokenPid && Number(tokenPid) !== Number(ptyPid)) {
    throw new Error('Token ptyPid does not match requested ptyPid.');
  }
}

function getClientSandboxHints(msg, payload) {
  const sandboxId = msg.sandboxId || msg.sandbox_id || payload.sandboxId || payload.sandbox_id || null;
  const ptyPid = normalizePid(msg.ptyPid || msg.pty_pid || msg.pid || payload.ptyPid || payload.pty_pid || payload.pid);

  if (sandboxId && ptyPid) validateResumeClaims(payload, sandboxId, ptyPid);

  return { sandboxId, ptyPid };
}

function getEnvironmentExpiryReason(record, now = Date.now()) {
  if (!record) return 'missing_record';
  if (record.status === 'expired') return 'record_marked_expired';
  if (record.status === 'error') return 'record_marked_error';
  if (record.expiresAt && now > record.expiresAt) return 'record_expires_at_elapsed';

  if (record.status === 'detached' && record.lastDetachedAt && now - record.lastDetachedAt > DETACHED_EXPIRE_MS) {
    return 'detached_expire_elapsed';
  }

  const attachedLikeStatus = !record.status || record.status === 'attached' || record.status === 'ready' || record.status === 'connecting';
  const hasRuntimeHandle = runtimeHandles.has(record.environmentKey);

  if (attachedLikeStatus && !hasRuntimeHandle && record.lastActiveAt) {
    const staleAgeMs = now - record.lastActiveAt;
    if (staleAgeMs > STALE_ATTACHED_RECREATE_MS) {
      return 'stale_attached_record';
    }
  }

  return null;
}

function isEnvironmentExpired(record, now = Date.now()) {
  return Boolean(getEnvironmentExpiryReason(record, now));
}

function publicRecord(record) {
  if (!record) return null;

  return {
    environmentId: record.environmentId,
    environmentKey: record.environmentKey,
    environmentMode: record.environmentMode,
    userId: record.userId,
    sandboxId: record.sandboxId,
    ptyPid: record.ptyPid,
    templateId: record.templateId,
    status: record.status,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    lastActiveAt: record.lastActiveAt,
    lastAttachedAt: record.lastAttachedAt,
    lastDetachedAt: record.lastDetachedAt,
    lastKeepAliveAt: record.lastKeepAliveAt || null,
    expiresAt: record.expiresAt,
    resetGeneration: record.resetGeneration || 0,
    staleReason: record.staleReason || null,
  };
}

async function refreshSandboxTimeout(handle, diagnosticId, force = false) {
  if (!handle?.sandbox || typeof handle.sandbox.setTimeout !== 'function') return false;

  const now = Date.now();
  if (!force && handle.lastTimeoutRefreshAt && now - handle.lastTimeoutRefreshAt < TIMEOUT_REFRESH_THROTTLE_MS) {
    return false;
  }

  try {
    await handle.sandbox.setTimeout(TERMINAL_IDLE_TIMEOUT_MS);
    handle.lastTimeoutRefreshAt = now;
    return true;
  } catch (error) {
    warnWithDiag(diagnosticId, '[timeout refresh failed]', safePublicError(error));
    return false;
  }
}

async function markEnvironmentActivity(environmentKey, diagnosticId) {
  if (!environmentKey) return;

  const record = await environmentStore.get(environmentKey);
  if (!record) return;

  const now = Date.now();
  const updated = {
    ...record,
    status: 'attached',
    lastActiveAt: now,
    lastKeepAliveAt: now,
    expiresAt: null,
    staleReason: null,
    diagnosticId,
  };

  await environmentStore.set(updated);

  const handle = runtimeHandles.get(environmentKey);
  if (handle) {
    handle.idleWarningSentAt = null;
    runtimeHandles.set(environmentKey, handle);
    await refreshSandboxTimeout(handle, diagnosticId);
  }
}

async function markEnvironmentKeepAlive(environmentKey, diagnosticId) {
  if (!environmentKey) return false;

  const record = await environmentStore.get(environmentKey);
  if (!record) return false;

  const now = Date.now();
  await environmentStore.set({
    ...record,
    status: record.status || 'attached',
    lastKeepAliveAt: now,
    diagnosticId,
  });

  return true;
}

async function disconnectRuntimeHandle(environmentKey, reason, options = {}) {
  const handle = runtimeHandles.get(environmentKey);
  if (!handle) return;

  const { closeWs = false, suppressDetach = true } = options;

  if (closeWs && handle.ws?.readyState === WS_OPEN) {
    handle.ws.__suppressDetach = suppressDetach;
    try {
      handle.ws.close(4000, reason);
    } catch {
      // Ignore close errors.
    }
  }

  try {
    if (handle.terminal && typeof handle.terminal.disconnect === 'function') {
      await handle.terminal.disconnect();
    }
  } catch (error) {
    warnWithDiag(handle.diagnosticId || 'no-diagnostic-id', '[runtime] terminal disconnect failed', safePublicError(error));
  }

  runtimeHandles.delete(environmentKey);
}

async function destroyEnvironment(record, reason, diagnosticId = 'no-diagnostic-id') {
  if (!record?.environmentKey) return;

  logWithDiag(diagnosticId, '[environment] destroy requested', {
    reason,
    environmentKey: record.environmentKey,
    sandboxId: record.sandboxId || '(none)',
    ptyPid: record.ptyPid || '(none)',
  });

  await disconnectRuntimeHandle(record.environmentKey, reason, { closeWs: true, suppressDetach: true });

  let sandbox = null;

  try {
    if (record.sandboxId) {
      sandbox = await withTimeout(
        Sandbox.connect(record.sandboxId, {
          apiKey: E2B_API_KEY,
          timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
          requestTimeoutMs: START_TIMEOUT_MS,
        }),
        START_TIMEOUT_MS,
        'Sandbox.connect for destroy'
      );
    }
  } catch (error) {
    warnWithDiag(diagnosticId, '[environment] destroy connect failed; assuming sandbox is already gone', safePublicError(error));
  }

  if (sandbox) {
    if (record.ptyPid) {
      try {
        await sandbox.pty.kill(record.ptyPid);
        logWithDiag(diagnosticId, '[environment] pty killed', { ptyPid: record.ptyPid });
      } catch (error) {
        warnWithDiag(diagnosticId, '[environment] pty kill failed', safePublicError(error));
      }
    }

    try {
      await sandbox.kill();
      logWithDiag(diagnosticId, '[environment] sandbox killed', { sandboxId: record.sandboxId });
    } catch (error) {
      warnWithDiag(diagnosticId, '[environment] sandbox kill failed', safePublicError(error));
    }
  }

  await environmentStore.delete(record.environmentKey);
}

function makeBaseEnvironmentRecord(request, diagnosticId, existing = {}) {
  const now = Date.now();

  return {
    environmentId: existing.environmentId || uuidv4(),
    environmentKey: request.environmentKey,
    environmentMode: request.environmentMode,
    userId: request.userId,
    templateId: request.templateId,
    sandboxId: existing.sandboxId || null,
    ptyPid: existing.ptyPid || null,
    status: existing.status || 'initializing',
    createdAt: existing.createdAt || now,
    updatedAt: now,
    lastActiveAt: existing.lastActiveAt || now,
    lastAttachedAt: existing.lastAttachedAt || null,
    lastDetachedAt: existing.lastDetachedAt || null,
    lastKeepAliveAt: existing.lastKeepAliveAt || null,
    expiresAt: existing.expiresAt || null,
    resetGeneration: existing.resetGeneration || 0,
    diagnosticId,
    adoptedFromClient: Boolean(existing.adoptedFromClient),
    lastError: null,
    staleReason: null,
  };
}

function createTerminalOutputHandler(ws, environmentKey, diagnosticId) {
  return (data) => {
    sendWsMessage(ws, {
      type: 'output',
      diagnosticId,
      environmentKey,
      data: Buffer.from(data).toString('base64'),
      encoding: 'base64',
    });

    markEnvironmentActivity(environmentKey, diagnosticId).catch((error) => {
      warnWithDiag(diagnosticId, '[activity] failed to record terminal output activity', safePublicError(error));
    });
  };
}

async function createAndAttachEnvironment(ws, msg, request, diagnosticId, options = {}) {
  const now = Date.now();
  const reason = options.reason || 'create';
  const previousRecord = options.previousRecord || null;
  const resetGeneration = options.resetGeneration || previousRecord?.resetGeneration || 0;

  let record = makeBaseEnvironmentRecord(request, diagnosticId, {
    environmentId: previousRecord?.environmentId,
    createdAt: previousRecord?.createdAt,
    resetGeneration,
  });

  logWithDiag(diagnosticId, '[environment] creating sandbox', {
    reason,
    environmentKey: request.environmentKey,
    environmentMode: request.environmentMode,
    templateId: request.templateId,
    terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
    rawTerminalIdleTimeoutMs: RAW_TERMINAL_IDLE_TIMEOUT_MS,
  });

  const sandbox = await withTimeout(
    Sandbox.create(request.templateId, {
      apiKey: E2B_API_KEY,
      timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      lifecycle: {
        onTimeout: 'pause',
        autoResume: false,
      },
      requestTimeoutMs: START_TIMEOUT_MS,
    }),
    START_TIMEOUT_MS,
    'Sandbox.create'
  );

  const sandboxId = sandbox.sandboxId;

  const terminal = await withTimeout(
    sandbox.pty.create({
      cols: msg.cols || 80,
      rows: msg.rows || 24,
      timeoutMs: 0,
      cwd: msg.cwd || '/home/user',
      envs: { TERM: 'xterm-256color', ...(msg.envs || {}) },
      onData: createTerminalOutputHandler(ws, request.environmentKey, diagnosticId),
    }),
    START_TIMEOUT_MS,
    'sandbox.pty.create'
  );

  record = {
    ...record,
    sandboxId,
    ptyPid: terminal.pid,
    status: 'attached',
    lastActiveAt: now,
    lastAttachedAt: now,
    lastDetachedAt: null,
    lastKeepAliveAt: now,
    expiresAt: null,
    diagnosticId,
  };

  runtimeHandles.set(request.environmentKey, {
    environmentKey: request.environmentKey,
    sandbox,
    terminal,
    ws,
    diagnosticId,
    idleWarningSentAt: null,
    lastTimeoutRefreshAt: 0,
  });

  await refreshSandboxTimeout(runtimeHandles.get(request.environmentKey), diagnosticId, true);
  await environmentStore.set(record);

  logWithDiag(diagnosticId, '[environment] ready', {
    environmentKey: request.environmentKey,
    environmentId: record.environmentId,
    sandboxId: record.sandboxId,
    ptyPid: record.ptyPid,
    created: true,
    reset: reason === 'reset',
  });

  sendWsMessage(ws, {
    type: 'ready',
    diagnosticId,
    protocol: 'environment-v1',
    environment: publicRecord(record),
    environmentId: record.environmentId,
    environmentKey: record.environmentKey,
    environmentMode: record.environmentMode,
    gatewaySessionId: record.environmentId,
    sandboxId: record.sandboxId,
    pid: record.ptyPid,
    ptyPid: record.ptyPid,
    resumed: false,
    created: true,
    reset: reason === 'reset',
    previousExpired: Boolean(options.previousExpired),
    previousExpiredReason: options.previousExpiredReason || null,
  });

  return record;
}

async function connectAndAttachEnvironment(ws, msg, record, diagnosticId, options = {}) {
  const now = Date.now();

  if (!record?.sandboxId || !record?.ptyPid) {
    throw new Error('Cannot attach existing environment without sandboxId and ptyPid.');
  }

  logWithDiag(diagnosticId, '[environment] connecting existing sandbox', {
    environmentKey: record.environmentKey,
    environmentId: record.environmentId,
    sandboxId: record.sandboxId,
    ptyPid: record.ptyPid,
    lastActiveAt: record.lastActiveAt,
    lastKeepAliveAt: record.lastKeepAliveAt,
  });

  const sandbox = await withTimeout(
    Sandbox.connect(record.sandboxId, {
      apiKey: E2B_API_KEY,
      timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      requestTimeoutMs: START_TIMEOUT_MS,
    }),
    START_TIMEOUT_MS,
    'Sandbox.connect'
  );

  const terminal = await withTimeout(
    sandbox.pty.connect(record.ptyPid, {
      onData: createTerminalOutputHandler(ws, record.environmentKey, diagnosticId),
    }),
    START_TIMEOUT_MS,
    'sandbox.pty.connect'
  );

  if (msg.cols && msg.rows) {
    await sandbox.pty.resize(record.ptyPid, {
      cols: msg.cols,
      rows: msg.rows,
    });
  }

  const updated = {
    ...record,
    status: 'attached',
    lastActiveAt: now,
    lastAttachedAt: now,
    lastDetachedAt: null,
    lastKeepAliveAt: now,
    expiresAt: null,
    diagnosticId,
    lastError: null,
    staleReason: null,
  };

  runtimeHandles.set(record.environmentKey, {
    environmentKey: record.environmentKey,
    sandbox,
    terminal,
    ws,
    diagnosticId,
    idleWarningSentAt: null,
    lastTimeoutRefreshAt: 0,
  });

  await refreshSandboxTimeout(runtimeHandles.get(record.environmentKey), diagnosticId, true);
  await environmentStore.set(updated);

  logWithDiag(diagnosticId, '[environment] attached', {
    environmentKey: updated.environmentKey,
    environmentId: updated.environmentId,
    sandboxId: updated.sandboxId,
    ptyPid: updated.ptyPid,
    resumed: true,
    adoptedFromClient: Boolean(options.adoptedFromClient),
  });

  sendWsMessage(ws, {
    type: 'ready',
    diagnosticId,
    protocol: 'environment-v1',
    environment: publicRecord(updated),
    environmentId: updated.environmentId,
    environmentKey: updated.environmentKey,
    environmentMode: updated.environmentMode,
    gatewaySessionId: updated.environmentId,
    sandboxId: updated.sandboxId,
    pid: updated.ptyPid,
    ptyPid: updated.ptyPid,
    resumed: true,
    created: false,
    reset: false,
    adoptedFromClient: Boolean(options.adoptedFromClient),
  });

  return updated;
}

async function attachOrCreateEnvironment(ws, msg, diagnosticId, options = {}) {
  const payload = verifyTerminalToken(msg.token);
  const request = resolveEnvironmentRequest(msg, payload);
  const hints = getClientSandboxHints(msg, payload);
  const now = Date.now();

  ws.__environmentKey = request.environmentKey;

  const existingHandle = runtimeHandles.get(request.environmentKey);
  if (existingHandle?.ws && existingHandle.ws !== ws) {
    logWithDiag(diagnosticId, '[environment] superseding prior websocket attachment', {
      environmentKey: request.environmentKey,
    });
    await disconnectRuntimeHandle(request.environmentKey, 'Superseded by a newer terminal attachment', {
      closeWs: true,
      suppressDetach: true,
    });
  }

  let record = await environmentStore.get(request.environmentKey);
  let previousExpired = false;
  let previousExpiredReason = null;
  let previousRecordForCreate = null;

  const expiryReason = getEnvironmentExpiryReason(record, now);
  if (record && expiryReason) {
    previousExpired = true;
    previousExpiredReason = expiryReason;
    previousRecordForCreate = {
      ...record,
      staleReason: expiryReason,
    };
    warnWithDiag(diagnosticId, '[environment] existing record expired before attach', {
      environmentKey: record.environmentKey,
      sandboxId: record.sandboxId,
      ptyPid: record.ptyPid,
      expiryReason,
      lastActiveAt: record.lastActiveAt,
      lastDetachedAt: record.lastDetachedAt,
      expiresAt: record.expiresAt,
    });
    await destroyEnvironment(record, `expired before attach: ${expiryReason}`, diagnosticId);
    record = null;
  }

  if (options.forceNew && record) {
    previousRecordForCreate = record;
    await destroyEnvironment(record, 'explicit reset before attach', diagnosticId);
    record = null;
  }

  if (!record && hints.sandboxId && hints.ptyPid && !previousExpired) {
    record = makeBaseEnvironmentRecord(request, diagnosticId, {
      sandboxId: hints.sandboxId,
      ptyPid: hints.ptyPid,
      status: 'detached',
      adoptedFromClient: true,
      resetGeneration: Number(msg.resetGeneration || msg.reset_generation || 0),
    });

    record.adoptedFromClient = true;
    await environmentStore.set(record);

    logWithDiag(diagnosticId, '[environment] adopted client-provided sandbox metadata', {
      environmentKey: request.environmentKey,
      sandboxId: record.sandboxId,
      ptyPid: record.ptyPid,
    });
  }

  if (record?.sandboxId && record?.ptyPid && !options.forceNew) {
    try {
      return await connectAndAttachEnvironment(ws, msg, record, diagnosticId, {
        adoptedFromClient: Boolean(record.adoptedFromClient),
      });
    } catch (error) {
      const message = safePublicError(error);
      warnWithDiag(diagnosticId, '[environment] attach existing failed; recreating environment', {
        environmentKey: request.environmentKey,
        sandboxId: record.sandboxId,
        ptyPid: record.ptyPid,
        message,
      });

      await environmentStore.set({
        ...record,
        status: 'expired',
        endedAt: Date.now(),
        lastError: message,
        staleReason: 'reattach_failed',
      });
      await destroyEnvironment(record, 'stale environment could not be reattached', diagnosticId);
      previousExpired = true;
      previousExpiredReason = 'reattach_failed';
      previousRecordForCreate = record;
    }
  }

  const seedRecord = previousRecordForCreate || record;
  const resetGeneration = options.forceNew
    ? Number(seedRecord?.resetGeneration || 0) + 1
    : Number(seedRecord?.resetGeneration || 0);

  return createAndAttachEnvironment(ws, msg, request, diagnosticId, {
    reason: options.forceNew ? 'reset' : 'create',
    previousRecord: seedRecord,
    resetGeneration,
    previousExpired,
    previousExpiredReason,
  });
}

async function detachEnvironmentForSocket(ws, diagnosticId) {
  const environmentKey = ws.__environmentKey;
  if (!environmentKey) return;

  const record = await environmentStore.get(environmentKey);
  const handle = runtimeHandles.get(environmentKey);

  logWithDiag(diagnosticId, '[environment] websocket detached', {
    environmentKey,
    sandboxId: record?.sandboxId || '(none)',
    ptyPid: record?.ptyPid || '(none)',
  });

  if (handle?.ws === ws) {
    try {
      if (handle.terminal && typeof handle.terminal.disconnect === 'function') {
        await handle.terminal.disconnect();
      }
    } catch (error) {
      warnWithDiag(diagnosticId, '[environment] detach terminal disconnect failed', safePublicError(error));
    }

    runtimeHandles.delete(environmentKey);
  }

  if (record) {
    const now = Date.now();
    await environmentStore.set({
      ...record,
      status: 'detached',
      lastDetachedAt: now,
      expiresAt: now + DETACHED_EXPIRE_MS,
      diagnosticId,
    });
  }
}

async function handleEnvironmentInput(ws, msg, diagnosticId) {
  const environmentKey = ws.__environmentKey;
  const handle = environmentKey ? runtimeHandles.get(environmentKey) : null;
  const record = environmentKey ? await environmentStore.get(environmentKey) : null;

  if (!handle?.sandbox || !handle?.terminal || !record?.ptyPid) {
    sendWsError(ws, diagnosticId, 'NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
    return;
  }

  await refreshSandboxTimeout(handle, diagnosticId);
  await handle.sandbox.pty.sendInput(record.ptyPid, new TextEncoder().encode(msg.data || ''));
  await markEnvironmentActivity(environmentKey, diagnosticId);
}

async function handleEnvironmentResize(ws, msg, diagnosticId) {
  const environmentKey = ws.__environmentKey;
  const handle = environmentKey ? runtimeHandles.get(environmentKey) : null;
  const record = environmentKey ? await environmentStore.get(environmentKey) : null;

  if (!handle?.sandbox || !handle?.terminal || !record?.ptyPid) {
    sendWsError(ws, diagnosticId, 'NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
    return;
  }

  if (!msg.cols || !msg.rows) {
    sendWsError(ws, diagnosticId, 'INVALID_RESIZE', 'Resize requires cols and rows.');
    return;
  }

  await refreshSandboxTimeout(handle, diagnosticId);
  await handle.sandbox.pty.resize(record.ptyPid, {
    cols: msg.cols,
    rows: msg.rows,
  });
  await markEnvironmentActivity(environmentKey, diagnosticId);
}

async function handleEnvironmentReset(ws, msg, diagnosticId) {
  return attachOrCreateEnvironment(ws, msg, diagnosticId, { forceNew: true });
}

async function handleHeartbeatPing(ws, msg, diagnosticId) {
  let refreshed = false;
  let keepAliveRecorded = false;

  if (ws.__environmentKey) {
    const handle = runtimeHandles.get(ws.__environmentKey);
    if (handle && REFRESH_SANDBOX_TIMEOUT_ON_PING) {
      refreshed = await refreshSandboxTimeout(handle, diagnosticId);
    }
    keepAliveRecorded = await markEnvironmentKeepAlive(ws.__environmentKey, diagnosticId);
  } else if (ws.__legacySessionId) {
    const session = legacySessions.get(ws.__legacySessionId);
    if (session && REFRESH_SANDBOX_TIMEOUT_ON_PING) {
      refreshed = await refreshSandboxTimeout(session, diagnosticId);
      session.lastKeepAliveAt = Date.now();
      legacySessions.set(ws.__legacySessionId, session);
    }
  }

  sendWsMessage(ws, {
    type: 'pong',
    diagnosticId,
    ts: Date.now(),
    environmentKey: ws.__environmentKey || null,
    sandboxTimeoutRefreshed: refreshed,
    keepAliveRecorded,
  });
}

async function handleRefreshToken(ws, msg, diagnosticId) {
  let tokenValid = false;
  let tokenEnvironmentKey = null;

  try {
    const payload = verifyTerminalToken(msg.token);
    tokenValid = true;
    tokenEnvironmentKey = payload.environmentKey || payload.environment_key || null;

    if (ws.__environmentKey && tokenEnvironmentKey && tokenEnvironmentKey !== ws.__environmentKey) {
      sendWsError(ws, diagnosticId, 'REFRESH_TOKEN_ENVIRONMENT_MISMATCH', 'Refreshed token environmentKey does not match active environment.');
      return;
    }
  } catch (error) {
    sendWsError(ws, diagnosticId, 'REFRESH_TOKEN_INVALID', safePublicError(error));
    return;
  }

  sendWsMessage(ws, {
    type: 'token_refreshed',
    diagnosticId,
    ts: Date.now(),
    tokenValid,
    environmentKey: ws.__environmentKey || tokenEnvironmentKey || null,
  });
}

async function getEnvironmentStatus(req, res) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length) : req.query.token;
    const payload = verifyTerminalToken(token);
    const request = resolveEnvironmentRequest(req.query, payload);
    const record = await environmentStore.get(request.environmentKey);
    const expiryReason = getEnvironmentExpiryReason(record);

    res.json({
      status: 'ok',
      exists: Boolean(record),
      expired: Boolean(expiryReason),
      expiryReason,
      environment: publicRecord(record),
    });
  } catch (error) {
    res.status(400).json({
      status: 'error',
      message: safePublicError(error),
    });
  }
}

app.get('/health', async (req, res) => {
  let records = [];
  let storeStatus = 'memory';

  try {
    records = await environmentStore.list();
    storeStatus = redis ? 'redis+memory-fallback' : 'memory';
  } catch (error) {
    storeStatus = `error: ${safePublicError(error)}`;
  }

  const byStatus = records.reduce((acc, record) => {
    acc[record.status || 'unknown'] = (acc[record.status || 'unknown'] || 0) + 1;
    return acc;
  }, {});

  const staleRecords = records
    .map((record) => ({ record, expiryReason: getEnvironmentExpiryReason(record) }))
    .filter((item) => Boolean(item.expiryReason));

  res.json({
    status: 'ok',
    uptime: process.uptime(),
    activeWebSocketClients: wss.clients.size,
    activeRuntimeHandles: runtimeHandles.size,
    legacyGatewaySessions: legacySessions.size,
    environmentRecords: records.length,
    environmentRecordsByStatus: byStatus,
    staleEnvironmentRecords: staleRecords.length,
    store: storeStatus,
    redis: {
      configured: Boolean(REDIS_URL),
      status: redis?.status || 'not_configured',
      lastErrorAt: environmentStore.lastRedisErrorAt,
    },
    config: {
      defaultTemplateId: DEFAULT_TEMPLATE_ID,
      rawTerminalIdleTimeoutMs: RAW_TERMINAL_IDLE_TIMEOUT_MS,
      terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      terminalIdleTimeoutClamped: TERMINAL_IDLE_TIMEOUT_MS !== RAW_TERMINAL_IDLE_TIMEOUT_MS,
      startTimeoutMs: START_TIMEOUT_MS,
      protocolHeartbeatMs: PROTOCOL_HEARTBEAT_MS,
      detachedGraceMs: DETACHED_GRACE_MS,
      detachedExpireMs: DETACHED_EXPIRE_MS,
      attachedIdleWarningMs: ATTACHED_IDLE_WARNING_MS,
      attachedIdleExpireAfterWarningMs: ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS,
      staleAttachedRecreateMs: STALE_ATTACHED_RECREATE_MS,
      environmentRecordTtlMs: ENVIRONMENT_RECORD_TTL_MS,
      environmentSweepMs: ENVIRONMENT_SWEEP_MS,
      timeoutRefreshThrottleMs: TIMEOUT_REFRESH_THROTTLE_MS,
      refreshSandboxTimeoutOnPing: REFRESH_SANDBOX_TIMEOUT_ON_PING,
      legacyStartCreatesNew: ENABLE_LEGACY_START_CREATES_NEW,
      allowedOriginsConfigured: ALLOWED_ORIGINS.length,
      allowedOriginSuffixesConfigured: ALLOWED_ORIGIN_SUFFIXES.length,
      websocketPath: '/terminal',
    },
  });
});

app.get('/environments/status', getEnvironmentStatus);

async function startLegacySession(ws, msg, diagnosticId) {
  verifyTerminalToken(msg.token);

  const sessionId = uuidv4();
  const templateId = getTemplateId(msg);

  logWithDiag(diagnosticId, '[legacy start] creating sandbox', {
    sessionId,
    templateId,
  });

  const sandbox = await withTimeout(
    Sandbox.create(templateId, {
      apiKey: E2B_API_KEY,
      timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      lifecycle: {
        onTimeout: 'pause',
        autoResume: false,
      },
      requestTimeoutMs: START_TIMEOUT_MS,
    }),
    START_TIMEOUT_MS,
    'Sandbox.create'
  );

  const terminal = await withTimeout(
    sandbox.pty.create({
      cols: msg.cols || 80,
      rows: msg.rows || 24,
      timeoutMs: 0,
      cwd: '/home/user',
      envs: { TERM: 'xterm-256color' },
      onData: (data) => {
        sendWsMessage(ws, {
          type: 'output',
          diagnosticId,
          data: Buffer.from(data).toString('base64'),
          encoding: 'base64',
        });
      },
    }),
    START_TIMEOUT_MS,
    'sandbox.pty.create'
  );

  const record = {
    sessionId,
    ws,
    sandbox,
    terminal,
    sandboxId: sandbox.sandboxId,
    ptyPid: terminal.pid,
    createdAt: Date.now(),
    lastActiveAt: Date.now(),
    lastKeepAliveAt: Date.now(),
    detachedAt: null,
    diagnosticId,
  };

  legacySessions.set(sessionId, record);
  ws.__legacySessionId = sessionId;

  sendWsMessage(ws, {
    type: 'ready',
    diagnosticId,
    protocol: 'legacy-session-v1',
    resumed: false,
    created: true,
    gatewaySessionId: sessionId,
    sandboxId: record.sandboxId,
    pid: record.ptyPid,
    ptyPid: record.ptyPid,
  });
}

async function resumeLegacySession(ws, msg, diagnosticId) {
  const payload = verifyTerminalToken(msg.token);

  const sandboxId = msg.sandboxId || payload.sandboxId;
  const ptyPid = normalizePid(msg.ptyPid || msg.pid || payload.ptyPid || payload.pid);

  if (!sandboxId || !ptyPid) {
    sendWsError(ws, diagnosticId, 'RESUME_MISSING_IDS', 'Cannot resume terminal: sandboxId and ptyPid are required.');
    return;
  }

  validateResumeClaims(payload, sandboxId, ptyPid);

  const sessionId = msg.gatewaySessionId || payload.gatewaySessionId || uuidv4();

  logWithDiag(diagnosticId, '[legacy resume] connecting', {
    sessionId,
    sandboxId,
    ptyPid,
  });

  const sandbox = await withTimeout(
    Sandbox.connect(sandboxId, {
      apiKey: E2B_API_KEY,
      timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      requestTimeoutMs: START_TIMEOUT_MS,
    }),
    START_TIMEOUT_MS,
    'Sandbox.connect'
  );

  const terminal = await withTimeout(
    sandbox.pty.connect(ptyPid, {
      onData: (data) => {
        sendWsMessage(ws, {
          type: 'output',
          diagnosticId,
          data: Buffer.from(data).toString('base64'),
          encoding: 'base64',
        });
      },
    }),
    START_TIMEOUT_MS,
    'sandbox.pty.connect'
  );

  if (msg.cols && msg.rows) {
    await sandbox.pty.resize(ptyPid, {
      cols: msg.cols,
      rows: msg.rows,
    });
  }

  legacySessions.set(sessionId, {
    sessionId,
    ws,
    sandbox,
    terminal,
    sandboxId,
    ptyPid,
    createdAt: Date.now(),
    lastActiveAt: Date.now(),
    lastKeepAliveAt: Date.now(),
    detachedAt: null,
    diagnosticId,
  });
  ws.__legacySessionId = sessionId;

  sendWsMessage(ws, {
    type: 'ready',
    diagnosticId,
    protocol: 'legacy-session-v1',
    resumed: true,
    created: false,
    gatewaySessionId: sessionId,
    sandboxId,
    pid: ptyPid,
    ptyPid,
  });
}

async function handleLegacyInput(ws, msg, diagnosticId) {
  const sessionId = ws.__legacySessionId;
  const session = sessionId ? legacySessions.get(sessionId) : null;

  if (!session?.sandbox || !session?.terminal || !session?.ptyPid) {
    sendWsError(ws, diagnosticId, 'NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
    return;
  }

  await refreshSandboxTimeout(session, diagnosticId);
  await session.sandbox.pty.sendInput(session.ptyPid, new TextEncoder().encode(msg.data || ''));
  session.lastActiveAt = Date.now();
  session.lastKeepAliveAt = Date.now();
  legacySessions.set(sessionId, session);
}

async function handleLegacyResize(ws, msg, diagnosticId) {
  const sessionId = ws.__legacySessionId;
  const session = sessionId ? legacySessions.get(sessionId) : null;

  if (!session?.sandbox || !session?.terminal || !session?.ptyPid) {
    sendWsError(ws, diagnosticId, 'NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
    return;
  }

  if (!msg.cols || !msg.rows) {
    sendWsError(ws, diagnosticId, 'INVALID_RESIZE', 'Resize requires cols and rows.');
    return;
  }

  await refreshSandboxTimeout(session, diagnosticId);
  await session.sandbox.pty.resize(session.ptyPid, {
    cols: msg.cols,
    rows: msg.rows,
  });
  session.lastActiveAt = Date.now();
  session.lastKeepAliveAt = Date.now();
  legacySessions.set(sessionId, session);
}

async function detachLegacySession(ws, diagnosticId) {
  const sessionId = ws.__legacySessionId;
  if (!sessionId) return;

  const session = legacySessions.get(sessionId);
  if (!session) return;

  try {
    if (session.terminal && typeof session.terminal.disconnect === 'function') {
      await session.terminal.disconnect();
    }
  } catch (error) {
    warnWithDiag(diagnosticId, '[legacy detach] terminal disconnect failed', safePublicError(error));
  }

  session.ws = null;
  session.terminal = null;
  session.detachedAt = Date.now();
  legacySessions.set(sessionId, session);
}

async function killLegacySession(ws, diagnosticId, reason = 'legacy explicit kill') {
  const sessionId = ws.__legacySessionId;
  if (!sessionId) return;

  const session = legacySessions.get(sessionId);
  if (!session) return;

  try {
    if (session.sandbox && session.ptyPid) {
      try {
        await session.sandbox.pty.kill(session.ptyPid);
      } catch (error) {
        warnWithDiag(diagnosticId, '[legacy kill] pty kill failed', safePublicError(error));
      }
    }

    if (session.sandbox) {
      try {
        await session.sandbox.kill();
      } catch (error) {
        warnWithDiag(diagnosticId, '[legacy kill] sandbox kill failed', safePublicError(error));
      }
    }
  } finally {
    legacySessions.delete(sessionId);
    logWithDiag(diagnosticId, '[legacy kill] complete', { sessionId, reason });
  }
}

wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;

  if (!isAllowedOrigin(origin)) {
    console.warn('[WS] rejected origin', origin || '(missing)');
    ws.close(1008, 'Origin not allowed');
    return;
  }

  console.log('[WS] new connection from', req.socket.remoteAddress, 'origin=', origin || '(missing)');

  ws.isAlive = true;
  ws.__environmentKey = null;
  ws.__legacySessionId = null;
  ws.__suppressDetach = false;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', async (data) => {
    const msg = parseJsonMessage(data);
    const diagnosticId = getDiagnosticId(msg);

    if (!msg || typeof msg.type !== 'string') {
      sendWsError(ws, diagnosticId, 'INVALID_MESSAGE', 'Invalid WebSocket message.');
      return;
    }

    try {
      if (msg.type === 'ping' || msg.type === 'heartbeat' || msg.type === 'keepalive') {
        await handleHeartbeatPing(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'refresh_token') {
        await handleRefreshToken(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'attach' || msg.type === 'get_or_create_environment') {
        await attachOrCreateEnvironment(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'reset' || msg.type === 'reset_environment') {
        await handleEnvironmentReset(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'start') {
        if (ENABLE_LEGACY_START_CREATES_NEW) {
          await startLegacySession(ws, msg, diagnosticId);
          return;
        }

        try {
          await attachOrCreateEnvironment(ws, msg, diagnosticId);
          return;
        } catch (error) {
          warnWithDiag(diagnosticId, '[start] environment attach failed; falling back to legacy start', safePublicError(error));
          await startLegacySession(ws, msg, diagnosticId);
          return;
        }
      }

      if (msg.type === 'resume' || msg.type === 'reconnect') {
        if (msg.environmentKey || msg.environment_key || msg.environmentMode || msg.environment_mode) {
          await attachOrCreateEnvironment(ws, msg, diagnosticId);
          return;
        }

        await resumeLegacySession(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'input') {
        if (ws.__environmentKey) {
          await handleEnvironmentInput(ws, msg, diagnosticId);
          return;
        }

        await handleLegacyInput(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'resize') {
        if (ws.__environmentKey) {
          await handleEnvironmentResize(ws, msg, diagnosticId);
          return;
        }

        await handleLegacyResize(ws, msg, diagnosticId);
        return;
      }

      if (msg.type === 'idle_confirm') {
        if (ws.__environmentKey) {
          await markEnvironmentActivity(ws.__environmentKey, diagnosticId);
          sendWsMessage(ws, {
            type: 'idle_confirmed',
            diagnosticId,
            environmentKey: ws.__environmentKey,
            ts: Date.now(),
          });
        }
        return;
      }

      if (msg.type === 'kill') {
        if (ws.__environmentKey) {
          const record = await environmentStore.get(ws.__environmentKey);
          if (record) await destroyEnvironment(record, 'explicit kill requested by client', diagnosticId);
        } else {
          await killLegacySession(ws, diagnosticId, 'explicit kill requested by client');
        }

        ws.close(1000, 'Killed by client');
        return;
      }

      sendWsError(ws, diagnosticId, 'UNSUPPORTED_MESSAGE', `Unsupported message type: ${msg.type}`);
    } catch (error) {
      const message = safePublicError(error);
      errorWithDiag(diagnosticId, '[msg error]', message);
      sendWsError(ws, diagnosticId, 'MESSAGE_HANDLER_FAILED', message);
    }
  });

  ws.on('close', async (code, reasonBuffer) => {
    const diagnosticId = 'ws-close';
    const reason = reasonBuffer?.toString?.() || '';

    console.log('[WS] closed', {
      code,
      reason,
      environmentKey: ws.__environmentKey || '(none)',
      legacySessionId: ws.__legacySessionId || '(none)',
      suppressDetach: Boolean(ws.__suppressDetach),
    });

    if (ws.__suppressDetach) return;

    try {
      if (ws.__environmentKey) {
        await detachEnvironmentForSocket(ws, diagnosticId);
      }

      if (ws.__legacySessionId) {
        await detachLegacySession(ws, diagnosticId);
      }
    } catch (error) {
      errorWithDiag(diagnosticId, '[close detach failed]', safePublicError(error));
    }
  });

  ws.on('error', (error) => {
    console.error('[WS] error', safePublicError(error));
  });
});

const protocolHeartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      console.warn('[WS] terminating dead socket');
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, PROTOCOL_HEARTBEAT_MS);

const environmentSweep = setInterval(async () => {
  const now = Date.now();

  try {
    const records = await environmentStore.list();

    for (const record of records) {
      if (!record?.environmentKey) continue;

      const handle = runtimeHandles.get(record.environmentKey);
      const expiryReason = getEnvironmentExpiryReason(record, now);

      if (record.status === 'detached' && record.lastDetachedAt) {
        if (expiryReason) {
          await destroyEnvironment(record, `environment sweep expired: ${expiryReason}`, record.diagnosticId || 'environment-sweep');
        }
        continue;
      }

      if (!handle && expiryReason) {
        warnWithDiag(record.diagnosticId || 'environment-sweep', '[environment sweep] stale record expired without active runtime handle', {
          environmentKey: record.environmentKey,
          expiryReason,
          lastActiveAt: record.lastActiveAt,
          lastDetachedAt: record.lastDetachedAt,
          expiresAt: record.expiresAt,
        });
        await destroyEnvironment(record, `environment sweep expired stale record: ${expiryReason}`, record.diagnosticId || 'environment-sweep');
        continue;
      }

      if (handle?.ws?.readyState === WS_OPEN && record.lastActiveAt) {
        const idleAgeMs = now - record.lastActiveAt;
        const warningDeadline = ATTACHED_IDLE_WARNING_MS;
        const expireDeadline = ATTACHED_IDLE_WARNING_MS + ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS;

        if (idleAgeMs > expireDeadline) {
          sendWsMessage(handle.ws, {
            type: 'expired',
            code: 'ATTACHED_IDLE_TIMEOUT',
            diagnosticId: record.diagnosticId || 'environment-sweep',
            environmentKey: record.environmentKey,
            idleAgeMs,
            message: 'Terminal environment expired after extended inactivity.',
          });
          await destroyEnvironment(record, 'attached idle timeout expired', record.diagnosticId || 'environment-sweep');
          continue;
        }

        if (idleAgeMs > warningDeadline && !handle.idleWarningSentAt) {
          handle.idleWarningSentAt = now;
          runtimeHandles.set(record.environmentKey, handle);
          sendWsMessage(handle.ws, {
            type: 'idle_warning',
            code: 'ARE_YOU_STILL_THERE',
            diagnosticId: record.diagnosticId || 'environment-sweep',
            environmentKey: record.environmentKey,
            idleAgeMs,
            expiresInMs: ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS,
            message: 'Are you still using this terminal and lesson?',
          });
        }
      }
    }
  } catch (error) {
    console.error('[environment sweep] failed', safePublicError(error));
  }
}, ENVIRONMENT_SWEEP_MS);

const legacySweep = setInterval(async () => {
  const now = Date.now();

  for (const [sessionId, session] of legacySessions.entries()) {
    if (!session.detachedAt) continue;

    if (now - session.detachedAt > DETACHED_EXPIRE_MS) {
      try {
        if (session.sandbox && session.ptyPid) {
          try {
            await session.sandbox.pty.kill(session.ptyPid);
          } catch {
            // Ignore stale PTY failures.
          }
        }

        if (session.sandbox) {
          try {
            await session.sandbox.kill();
          } catch {
            // Ignore stale sandbox failures.
          }
        }
      } finally {
        legacySessions.delete(sessionId);
        console.log('[legacy sweep] pruned detached legacy session', { sessionId });
      }
    }
  }
}, ENVIRONMENT_SWEEP_MS);

wss.on('close', () => {
  clearInterval(protocolHeartbeat);
  clearInterval(environmentSweep);
  clearInterval(legacySweep);
});

process.on('SIGTERM', () => {
  console.log('[gateway] SIGTERM received; closing HTTP server without killing learner environments');
  server.close(() => {
    process.exit(0);
  });
});

server.listen(PORT, () => {
  console.log(`[gateway] listening on port ${PORT}`);
  console.log('[gateway] config', {
    defaultTemplateId: DEFAULT_TEMPLATE_ID,
    rawTerminalIdleTimeoutMs: RAW_TERMINAL_IDLE_TIMEOUT_MS,
    terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
    terminalIdleTimeoutClamped: TERMINAL_IDLE_TIMEOUT_MS !== RAW_TERMINAL_IDLE_TIMEOUT_MS,
    startTimeoutMs: START_TIMEOUT_MS,
    protocolHeartbeatMs: PROTOCOL_HEARTBEAT_MS,
    detachedGraceMs: DETACHED_GRACE_MS,
    detachedExpireMs: DETACHED_EXPIRE_MS,
    attachedIdleWarningMs: ATTACHED_IDLE_WARNING_MS,
    attachedIdleExpireAfterWarningMs: ATTACHED_IDLE_EXPIRE_AFTER_WARNING_MS,
    staleAttachedRecreateMs: STALE_ATTACHED_RECREATE_MS,
    environmentRecordTtlMs: ENVIRONMENT_RECORD_TTL_MS,
    environmentSweepMs: ENVIRONMENT_SWEEP_MS,
    timeoutRefreshThrottleMs: TIMEOUT_REFRESH_THROTTLE_MS,
    refreshSandboxTimeoutOnPing: REFRESH_SANDBOX_TIMEOUT_ON_PING,
    redisConfigured: Boolean(REDIS_URL),
    legacyStartCreatesNew: ENABLE_LEGACY_START_CREATES_NEW,
    allowedOriginsConfigured: ALLOWED_ORIGINS.length,
    allowedOriginSuffixesConfigured: ALLOWED_ORIGIN_SUFFIXES.length,
    websocketPath: '/terminal',
  });
});
