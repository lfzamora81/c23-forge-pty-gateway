import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { Sandbox } from 'e2b';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const PORT = process.env.PORT || 10000;
const E2B_API_KEY = process.env.E2B_API_KEY;
const TERMINAL_TOKEN_SECRET = process.env.TERMINAL_TOKEN_SECRET;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
const SESSION_GRACE_MS = parseInt(process.env.SESSION_GRACE_MS || '300000', 10);
const IDLE_TIMEOUT_MS = parseInt(process.env.IDLE_TIMEOUT_MS || '1800000', 10);
const SANDBOX_TIMEOUT_MS = parseInt(process.env.SANDBOX_TIMEOUT_MS || '3600000', 10);
const DEFAULT_TEMPLATE_ID = process.env.DEFAULT_TEMPLATE_ID || 'base';
const TERMINAL_IDLE_TIMEOUT_MS = parseInt(
  process.env.TERMINAL_IDLE_TIMEOUT_MS || process.env.IDLE_TIMEOUT_MS || '7200000',
  10
);

if (!E2B_API_KEY) throw new Error('E2B_API_KEY required');
if (!TERMINAL_TOKEN_SECRET) throw new Error('TERMINAL_TOKEN_SECRET required');

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server });

app.use(cors());
app.use(express.json());

const sessions = new Map();

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

wss.on('connection', (ws, req) => {
  console.log('[WS] new connection from', req.socket.remoteAddress);
  let sessionId = null;
  let sandbox = null;
  let terminal = null;
  let heartbeatInterval = null;

  const sendMessage = (msg) => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(msg));
    }
  };

  const cleanupSession = async () => {
    try {
      if (terminal && sandbox) await sandbox.pty.kill(terminal.pid);
      if (sandbox) await sandbox.kill();
      if (sessionId) sessions.delete(sessionId);
    } catch (e) { console.error('[cleanup]', e.message); }
  };

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());
      
      if (msg.type === 'ping') {
        sendMessage({
        type: 'pong',
        ts: Date.now()
        });
        return;
      }
      
      if (msg.type === 'start') {
        const payload = jwt.verify(msg.token, TERMINAL_TOKEN_SECRET, { algorithms: ['HS256'] });
        sessionId = uuidv4();
        sandbox = await Sandbox.create(msg.template || DEFAULT_TEMPLATE_ID, {
          apiKey: E2B_API_KEY,
          timeoutMs: TERMINAL_IDLE_TIMEOUT_MS,
          lifecycle: {
            onTimeout: 'pause',
            autoResume: false
          }
        });
        terminal = await sandbox.pty.create({
          cols: msg.cols || 80,
          rows: msg.rows || 24,
          timeoutMs: 0,
          cwd: '/home/user',
          envs: { TERM: 'xterm-256color' },
          onData: (data) => sendMessage({
            type: 'output',
            data: Buffer.from(data).toString('base64'),
            encoding: 'base64'
            }),
        });
        sessions.set(sessionId, { ws, sandbox, terminal });
        sendMessage({ type: 'ready', sandboxId: sandbox.sandboxId, pid: terminal.pid });
      } else if (msg.type === 'resume') {
        const payload = jwt.verify(msg.token, TERMINAL_TOKEN_SECRET, { algorithms: ['HS256'] });

        const sandboxId = msg.sandboxId || payload.sandboxId;
        const ptyPid = msg.ptyPid || msg.pid || payload.ptyPid || payload.pid;

        if (!sandboxId || !ptyPid) {
          sendMessage({
            type: 'error',
            message: 'Cannot resume terminal: sandboxId and ptyPid are required.'
          });
          return;
        }

        sessionId = msg.gatewaySessionId || payload.gatewaySessionId || uuidv4();

        sandbox = await Sandbox.connect(sandboxId, {
          apiKey: E2B_API_KEY,
          timeoutMs: TERMINAL_IDLE_TIMEOUT_MS
        });

        terminal = await sandbox.pty.connect(Number(ptyPid), {
          onData: (data) => sendMessage({
            type: 'output',
            data: Buffer.from(data).toString('base64'),
            encoding: 'base64'
          })
        });

        if (msg.cols && msg.rows) {
          await sandbox.pty.resize(Number(ptyPid), {
            cols: msg.cols,
            rows: msg.rows
          });
        }

        sessions.set(sessionId, {
          ws,
          sandbox,
          terminal,
          sandboxId,
          ptyPid: Number(ptyPid),
          lastActiveAt: Date.now()
        });

        sendMessage({
          type: 'ready',
          resumed: true,
          gatewaySessionId: sessionId,
          sandboxId,
          pid: Number(ptyPid),
          ptyPid: Number(ptyPid)
        });

      else if (msg.type === 'input' && terminal) {
        if (typeof sandbox?.setTimeout === 'function') {
          await sandbox.setTimeout(SANDBOX_TIMEOUT_MS);
        }

        await sandbox.pty.sendInput(
          terminal.pid,
          new TextEncoder().encode(msg.data)
        );
      } else if (msg.type === 'resize' && terminal) {
        if (typeof sandbox?.setTimeout === 'function') {
          await sandbox.setTimeout(SANDBOX_TIMEOUT_MS);
        }

        await sandbox.pty.resize(terminal.pid, {
          cols: msg.cols,
          rows: msg.rows
        });
      } else if (msg.type === 'kill') {
        await cleanupSession();
        ws.close();
      }
    } catch (e) { console.error('[msg error]', e.message); }
  });

  ws.on('close', async () => {
  console.log('[WS] detached', sessionId || '(unstarted)');

    try {
      if (terminal && typeof terminal.disconnect === 'function') {
        await terminal.disconnect();
      }
    } catch (e) {
      console.warn('[detach] terminal disconnect failed:', e.message);
    }

    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId);
      session.ws = null;
      session.terminal = null;
      session.detachedAt = Date.now();
      sessions.set(sessionId, session);
    }
  });
});

server.listen(PORT, () => console.log(`[gateway] listening on port ${PORT}`));
