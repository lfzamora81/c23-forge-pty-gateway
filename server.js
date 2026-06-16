import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Sandbox } from 'e2b';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const WS_OPEN = 1;

const parseMs = (value, fallback) => {
  const parsed = Number.parseInt(value || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const PORT = process.env.PORT || 10000;
const E2B_API_KEY = process.env.E2B_API_KEY;
const TERMINAL_TOKEN_SECRET = process.env.TERMINAL_TOKEN_SECRET;

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

const TERMINAL_IDLE_TIMEOUT_MS = parseMs(
  process.env.TERMINAL_IDLE_TIMEOUT_MS ||
    process.env.SANDBOX_TIMEOUT_MS ||
    process.env.IDLE_TIMEOUT_MS,
  60 * 60 * 1000
);

const START_TIMEOUT_MS = parseMs(process.env.START_TIMEOUT_MS, 90 * 1000);
const PROTOCOL_HEARTBEAT_MS = parseMs(process.env.PROTOCOL_HEARTBEAT_MS, 30 * 1000);
const DETACHED_RECORD_TTL_MS = parseMs(
  process.env.DETACHED_RECORD_TTL_MS,
  6 * 60 * 60 * 1000
);

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

const sessions = new Map();

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

  const isLocalhost =
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1';

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
  return jwt.verify(token, TERMINAL_TOKEN_SECRET, { algorithms: ['HS256'] });
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

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    activeGatewaySessions: sessions.size,
    config: {
      defaultTemplateId: DEFAULT_TEMPLATE_ID,
      terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
      startTimeoutMs: START_TIMEOUT_MS,
      protocolHeartbeatMs: PROTOCOL_HEARTBEAT_MS,
      detachedRecordTtlMs: DETACHED_RECORD_TTL_MS,
      allowedOriginsConfigured: ALLOWED_ORIGINS.length,
      allowedOriginSuffixesConfigured: ALLOWED_ORIGIN_SUFFIXES.length,
      websocketPath: '/terminal',
    },
  });
});

wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;

  if (!isAllowedOrigin(origin)) {
    console.warn('[WS] rejected origin', origin || '(missing)');
    ws.close(1008, 'Origin not allowed');
    return;
  }

  console.log('[WS] new connection from', req.socket.remoteAddress, 'origin=', origin || '(missing)');

  ws.isAlive = true;

  let sessionId = null;
  let sandbox = null;
  let terminal = null;
  let ptyPid = null;
  let sandboxId = null;
  let readySent = false;
  let createdSandboxInThisConnection = false;
  let detached = false;
  let currentDiagnosticId = 'no-diagnostic-id';

  const sendMessage = (msg) => {
    if (ws.readyState === WS_OPEN) {
      ws.send(JSON.stringify(msg));
      return true;
    }

    return false;
  };

  const sendError = (code, message, extra = {}) => {
    const payload = {
      type: 'error',
      code,
      message,
      diagnosticId: currentDiagnosticId,
      ...extra,
    };

    errorWithDiag(currentDiagnosticId, `[gateway error] ${code}: ${message}`);
    sendMessage(payload);
  };

  const refreshSandboxTimeout = async () => {
    if (!sandbox || typeof sandbox.setTimeout !== 'function') return;

    try {
      await sandbox.setTimeout(TERMINAL_IDLE_TIMEOUT_MS);
    } catch (error) {
      const message = safePublicError(error);
      warnWithDiag(currentDiagnosticId, '[timeout refresh failed]', message);
      sendMessage({
        type: 'warning',
        code: 'TIMEOUT_REFRESH_FAILED',
        diagnosticId: currentDiagnosticId,
        message,
      });
    }
  };

  const rememberSession = (record) => {
    if (!sessionId) return;

    sessions.set(sessionId, {
      sessionId,
      ws,
      sandbox,
      terminal,
      sandboxId,
      ptyPid,
      lastActiveAt: Date.now(),
      detachedAt: null,
      diagnosticId: currentDiagnosticId,
      ...record,
    });
  };

  const markActivity = () => {
    if (!sessionId || !sessions.has(sessionId)) return;

    const session = sessions.get(sessionId);
    session.lastActiveAt = Date.now();
    session.diagnosticId = currentDiagnosticId;
    sessions.set(sessionId, session);
  };

  const detachSession = async () => {
    if (detached) return;
    detached = true;

    logWithDiag(currentDiagnosticId, '[WS] detached', {
      sessionId: sessionId || '(unstarted)',
      sandboxId: sandboxId || '(none)',
      ptyPid: ptyPid || '(none)',
      readySent,
    });

    try {
      if (terminal && typeof terminal.disconnect === 'function') {
        await terminal.disconnect();
      }
    } catch (error) {
      warnWithDiag(currentDiagnosticId, '[detach] terminal disconnect failed', safePublicError(error));
    }

    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId);
      session.ws = null;
      session.terminal = null;
      session.detachedAt = Date.now();
      session.diagnosticId = currentDiagnosticId;
      sessions.set(sessionId, session);
    }
  };

  const cleanupSession = async (reason = 'cleanup requested') => {
    logWithDiag(currentDiagnosticId, '[cleanup] requested', {
      reason,
      sessionId: sessionId || '(unstarted)',
      sandboxId: sandboxId || '(none)',
      ptyPid: ptyPid || '(none)',
    });

    try {
      if (terminal && sandbox && ptyPid) {
        try {
          await sandbox.pty.kill(ptyPid);
          logWithDiag(currentDiagnosticId, '[cleanup] pty killed', { ptyPid });
        } catch (error) {
          warnWithDiag(currentDiagnosticId, '[cleanup] pty kill failed', safePublicError(error));
        }
      }

      if (sandbox) {
        try {
          await sandbox.kill();
          logWithDiag(currentDiagnosticId, '[cleanup] sandbox killed', {
            sandboxId: sandboxId || sandbox.sandboxId,
          });
        } catch (error) {
          warnWithDiag(currentDiagnosticId, '[cleanup] sandbox kill failed', safePublicError(error));
        }
      }

      if (sessionId) sessions.delete(sessionId);
    } catch (error) {
      errorWithDiag(currentDiagnosticId, '[cleanup] failed', safePublicError(error));
    }
  };

  const startSession = async (msg) => {
    currentDiagnosticId = getDiagnosticId(msg);

    if (sandbox || terminal) {
      sendError('SESSION_ALREADY_STARTED', 'This WebSocket already has a terminal session.');
      return;
    }

    verifyTerminalToken(msg.token);

    sessionId = uuidv4();
    const templateId = getTemplateId(msg);

    logWithDiag(currentDiagnosticId, '[start] creating sandbox', {
      sessionId,
      templateId,
      terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
    });

    try {
      sandbox = await withTimeout(
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

      createdSandboxInThisConnection = true;
      sandboxId = sandbox.sandboxId;

      logWithDiag(currentDiagnosticId, '[start] sandbox created', {
        sessionId,
        sandboxId,
      });

      terminal = await withTimeout(
        sandbox.pty.create({
          cols: msg.cols || 80,
          rows: msg.rows || 24,
          timeoutMs: 0,
          cwd: '/home/user',
          envs: { TERM: 'xterm-256color' },
          onData: (data) => {
            sendMessage({
              type: 'output',
              diagnosticId: currentDiagnosticId,
              data: Buffer.from(data).toString('base64'),
              encoding: 'base64',
            });
          },
        }),
        START_TIMEOUT_MS,
        'sandbox.pty.create'
      );

      ptyPid = terminal.pid;

      if (ws.readyState !== WS_OPEN) {
        await cleanupSession('socket closed before ready');
        return;
      }

      readySent = true;

      rememberSession({
        createdAt: Date.now(),
        resumed: false,
      });

      logWithDiag(currentDiagnosticId, '[start] ready', {
        sessionId,
        sandboxId,
        ptyPid,
      });

      sendMessage({
        type: 'ready',
        diagnosticId: currentDiagnosticId,
        resumed: false,
        gatewaySessionId: sessionId,
        sandboxId,
        pid: ptyPid,
        ptyPid,
      });
    } catch (error) {
      const message = safePublicError(error);
      sendError('START_FAILED', `Start failed: ${message}`);

      if (createdSandboxInThisConnection) {
        await cleanupSession('start failed after sandbox creation');
      }
    }
  };

  const resumeSession = async (msg) => {
    currentDiagnosticId = getDiagnosticId(msg);

    if (sandbox || terminal) {
      sendError('SESSION_ALREADY_STARTED', 'This WebSocket already has a terminal session.');
      return;
    }

    const payload = verifyTerminalToken(msg.token);

    sandboxId = msg.sandboxId || payload.sandboxId;
    ptyPid = normalizePid(msg.ptyPid || msg.pid || payload.ptyPid || payload.pid);

    if (!sandboxId || !ptyPid) {
      sendError(
        'RESUME_MISSING_IDS',
        'Cannot resume terminal: sandboxId and ptyPid are required.'
      );
      return;
    }

    validateResumeClaims(payload, sandboxId, ptyPid);

    sessionId = msg.gatewaySessionId || payload.gatewaySessionId || uuidv4();

    logWithDiag(currentDiagnosticId, '[resume] connecting', {
      sessionId,
      sandboxId,
      ptyPid,
      terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
    });

    try {
      sandbox = await withTimeout(
        Sandbox.connect(sandboxId, {
          apiKey: E2B_API_KEY,
          timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
          requestTimeoutMs: START_TIMEOUT_MS,
        }),
        START_TIMEOUT_MS,
        'Sandbox.connect'
      );

      terminal = await withTimeout(
        sandbox.pty.connect(ptyPid, {
          onData: (data) => {
            sendMessage({
              type: 'output',
              diagnosticId: currentDiagnosticId,
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

      if (ws.readyState !== WS_OPEN) {
        await detachSession();
        return;
      }

      readySent = true;

      rememberSession({
        resumed: true,
      });

      logWithDiag(currentDiagnosticId, '[resume] ready', {
        sessionId,
        sandboxId,
        ptyPid,
      });

      sendMessage({
        type: 'ready',
        diagnosticId: currentDiagnosticId,
        resumed: true,
        gatewaySessionId: sessionId,
        sandboxId,
        pid: ptyPid,
        ptyPid,
      });
    } catch (error) {
      const message = safePublicError(error);

      errorWithDiag(currentDiagnosticId, '[resume failed]', {
        sessionId,
        sandboxId,
        ptyPid,
        message,
      });

      sendError('RESUME_FAILED', `Resume failed: ${message}`, {
        sandboxId,
        ptyPid,
      });
    }
  };

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', async (data) => {
    const msg = parseJsonMessage(data);

    if (!msg || typeof msg.type !== 'string') {
      sendError('INVALID_MESSAGE', 'Invalid WebSocket message.');
      return;
    }

    currentDiagnosticId = getDiagnosticId(msg);

    try {
      if (msg.type === 'ping') {
        sendMessage({
          type: 'pong',
          diagnosticId: currentDiagnosticId,
          ts: Date.now(),
        });
        return;
      }

      if (msg.type === 'start') {
        await startSession(msg);
        return;
      }

      if (msg.type === 'resume' || msg.type === 'reconnect') {
        await resumeSession(msg);
        return;
      }

      if (msg.type === 'input') {
        if (!sandbox || !terminal || !ptyPid) {
          sendError('NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
          return;
        }

        await refreshSandboxTimeout();
        await sandbox.pty.sendInput(
          ptyPid,
          new TextEncoder().encode(msg.data || '')
        );

        markActivity();
        return;
      }

      if (msg.type === 'resize') {
        if (!sandbox || !terminal || !ptyPid) {
          sendError('NO_ACTIVE_TERMINAL', 'No active terminal is attached to this WebSocket.');
          return;
        }

        if (!msg.cols || !msg.rows) {
          sendError('INVALID_RESIZE', 'Resize requires cols and rows.');
          return;
        }

        await refreshSandboxTimeout();
        await sandbox.pty.resize(ptyPid, {
          cols: msg.cols,
          rows: msg.rows,
        });

        markActivity();
        return;
      }

      if (msg.type === 'kill') {
        await cleanupSession('explicit kill requested by client');
        ws.close(1000, 'Killed by client');
        return;
      }

      sendError('UNSUPPORTED_MESSAGE', `Unsupported message type: ${msg.type}`);
    } catch (error) {
      const message = safePublicError(error);
      errorWithDiag(currentDiagnosticId, '[msg error]', message);
      sendError('MESSAGE_HANDLER_FAILED', message);
    }
  });

  ws.on('close', async (code, reasonBuffer) => {
    const reason = reasonBuffer?.toString?.() || '';

    logWithDiag(currentDiagnosticId, '[WS] closed', {
      code,
      reason,
      readySent,
      createdSandboxInThisConnection,
    });

    if (!readySent && createdSandboxInThisConnection) {
      await cleanupSession('socket closed before ready');
      return;
    }

    await detachSession();
  });

  ws.on('error', (error) => {
    errorWithDiag(currentDiagnosticId, '[WS] error', safePublicError(error));
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

const pruneDetachedRecords = setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions.entries()) {
    if (!session.detachedAt) continue;

    const ageMs = now - session.detachedAt;
    if (ageMs > DETACHED_RECORD_TTL_MS) {
      sessions.delete(id);
      console.log('[sessions] pruned detached record', {
        sessionId: id,
        diagnosticId: session.diagnosticId || 'no-diagnostic-id',
        ageMs,
      });
    }
  }
}, Math.min(DETACHED_RECORD_TTL_MS, 60 * 60 * 1000));

wss.on('close', () => {
  clearInterval(protocolHeartbeat);
  clearInterval(pruneDetachedRecords);
});

server.listen(PORT, () => {
  console.log(`[gateway] listening on port ${PORT}`);
  console.log('[gateway] config', {
    defaultTemplateId: DEFAULT_TEMPLATE_ID,
    terminalIdleTimeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
    startTimeoutMs: START_TIMEOUT_MS,
    protocolHeartbeatMs: PROTOCOL_HEARTBEAT_MS,
    detachedRecordTtlMs: DETACHED_RECORD_TTL_MS,
    allowedOriginsConfigured: ALLOWED_ORIGINS.length,
    allowedOriginSuffixesConfigured: ALLOWED_ORIGIN_SUFFIXES.length,
    websocketPath: '/terminal',
  });
});
