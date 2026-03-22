import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createProxy, parseRoute } from '../lib/proxy.mjs';

// ── helpers ────────────────────────────────────────────────────────────────

/** Simple HTTP request returning { statusCode, headers, body } */
function request(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString(),
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** Collect all SSE data from a streaming response */
function requestSSE(options, body) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c.toString()));
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: chunks.join('') }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/** Start a bare http.Server that calls handler for every request. Returns server with .port */
function startMock(handler) {
  return new Promise((resolve, reject) => {
    const s = http.createServer(handler);
    s.listen(0, '127.0.0.1', () => {
      s.port = s.address().port;
      resolve(s);
    });
    s.on('error', reject);
  });
}

function stopMock(s) {
  return new Promise(r => s.close(r));
}

// ── parseRoute unit tests ──────────────────────────────────────────────────

describe('parseRoute', () => {
  test('basic service + path', () => {
    const r = parseRoute('/anthropic/v1/messages');
    assert.strictEqual(r.service, 'anthropic');
    assert.strictEqual(r.path, '/v1/messages');
    assert.strictEqual(r.query, '');
  });

  test('path with query string', () => {
    const r = parseRoute('/google/v1/models?key=AIza-xxx&foo=bar');
    assert.strictEqual(r.service, 'google');
    assert.strictEqual(r.path, '/v1/models');
    assert.strictEqual(r.query, '?key=AIza-xxx&foo=bar');
  });

  test('service with trailing slash', () => {
    const r = parseRoute('/openai/');
    assert.strictEqual(r.service, 'openai');
    assert.strictEqual(r.path, '/');
    assert.strictEqual(r.query, '');
  });

  test('service only, no trailing slash', () => {
    const r = parseRoute('/openai');
    assert.strictEqual(r.service, 'openai');
    assert.strictEqual(r.path, '/');
    assert.strictEqual(r.query, '');
  });

  test('root path returns null', () => {
    assert.strictEqual(parseRoute('/'), null);
  });

  test('empty string returns null', () => {
    assert.strictEqual(parseRoute(''), null);
  });

  test('deeply nested path', () => {
    const r = parseRoute('/anthropic/v1/messages/stream?a=1');
    assert.strictEqual(r.service, 'anthropic');
    assert.strictEqual(r.path, '/v1/messages/stream');
    assert.strictEqual(r.query, '?a=1');
  });
});

// ── proxy integration tests ────────────────────────────────────────────────

describe('proxy', () => {
  let proxy;

  before(async () => {
    proxy = await createProxy({ port: 0, dataDir: '/tmp', serverPort: 8443 });
  });

  after(async () => {
    await proxy.close();
  });

  beforeEach(() => {
    // Always start each test in locked state
    proxy.lock();
  });

  // ── health ──────────────────────────────────────────────────────────────

  test('GET /health returns ok + locked state (locked)', async () => {
    const res = await request({ hostname: '127.0.0.1', port: proxy.port, path: '/health', method: 'GET' });
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.status, 'ok');
    assert.strictEqual(body.locked, true);
  });

  test('GET /health returns ok + locked state (unlocked)', async () => {
    proxy.setSecrets({ version: 1, services: {} });
    const res = await request({ hostname: '127.0.0.1', port: proxy.port, path: '/health', method: 'GET' });
    const body = JSON.parse(res.body);
    assert.strictEqual(body.status, 'ok');
    assert.strictEqual(body.locked, false);
  });

  // ── locked mode ─────────────────────────────────────────────────────────

  test('locked: JSON response for non-stream request', async () => {
    assert.ok(proxy.isLocked());
    const res = await request(
      { hostname: '127.0.0.1', port: proxy.port, path: '/openai/v1/chat/completions', method: 'POST',
        headers: { 'Content-Type': 'application/json' } },
      JSON.stringify({ model: 'gpt-4o', messages: [] }),
    );
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.id, 'safeclaw-locked');
    assert.strictEqual(body.object, 'chat.completion');
    assert.ok(body.choices[0].message.content.includes('locked'));
    assert.strictEqual(body.choices[0].finish_reason, 'stop');
  });

  test('locked: SSE response when stream:true in body', async () => {
    const res = await requestSSE(
      { hostname: '127.0.0.1', port: proxy.port, path: '/openai/v1/chat/completions', method: 'POST',
        headers: { 'Content-Type': 'application/json' } },
      JSON.stringify({ model: 'gpt-4o', messages: [], stream: true }),
    );
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.headers['content-type'].includes('text/event-stream'));
    assert.ok(res.body.includes('data: '));
    assert.ok(res.body.includes('[DONE]'));
    // Parse the first data chunk
    const firstLine = res.body.split('\n').find(l => l.startsWith('data: ') && !l.includes('[DONE]'));
    const chunk = JSON.parse(firstLine.slice(6));
    assert.ok(chunk.choices[0].message.content.includes('locked'));
  });

  test('locked: non-JSON body still returns locked JSON response', async () => {
    const res = await request(
      { hostname: '127.0.0.1', port: proxy.port, path: '/openai/v1/chat/completions', method: 'POST' },
      'not json',
    );
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.id, 'safeclaw-locked');
  });

  // ── auth injection ───────────────────────────────────────────────────────

  test('auth injection: type=header (no prefix)', async () => {
    let receivedHeaders;
    const mock = await startMock((req, res) => {
      receivedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          mysvc: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: { type: 'header', name: 'x-api-key', value: 'sk-test-123' },
          },
        },
      });

      const res = await request({ hostname: '127.0.0.1', port: proxy.port, path: '/mysvc/v1/test', method: 'GET' });
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(receivedHeaders['x-api-key'], 'sk-test-123');
      assert.ok(!receivedHeaders['host'].includes('127.0.0.1:' + proxy.port)); // host rewritten
    } finally {
      await stopMock(mock);
    }
  });

  test('auth injection: type=header with Bearer prefix', async () => {
    let receivedHeaders;
    const mock = await startMock((req, res) => {
      receivedHeaders = req.headers;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          openai: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: { type: 'header', name: 'Authorization', prefix: 'Bearer', value: 'sk-openai-abc' },
          },
        },
      });

      await request({ hostname: '127.0.0.1', port: proxy.port, path: '/openai/v1/chat', method: 'GET' });
      assert.strictEqual(receivedHeaders['authorization'], 'Bearer sk-openai-abc');
    } finally {
      await stopMock(mock);
    }
  });

  test('auth injection: type=query', async () => {
    let receivedUrl;
    const mock = await startMock((req, res) => {
      receivedUrl = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          google: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: { type: 'query', name: 'key', value: 'AIza-xxx' },
          },
        },
      });

      await request({ hostname: '127.0.0.1', port: proxy.port, path: '/google/v1/models', method: 'GET' });
      assert.ok(receivedUrl.includes('key=AIza-xxx'), `Expected key param in: ${receivedUrl}`);
    } finally {
      await stopMock(mock);
    }
  });

  test('auth injection: type=query preserves existing query params', async () => {
    let receivedUrl;
    const mock = await startMock((req, res) => {
      receivedUrl = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          google: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: { type: 'query', name: 'key', value: 'AIza-xxx' },
          },
        },
      });

      await request({ hostname: '127.0.0.1', port: proxy.port, path: '/google/v1/models?alt=json', method: 'GET' });
      assert.ok(receivedUrl.includes('alt=json'));
      assert.ok(receivedUrl.includes('key=AIza-xxx'));
    } finally {
      await stopMock(mock);
    }
  });

  test('auth injection: type=path prepends value to path', async () => {
    let receivedUrl;
    const mock = await startMock((req, res) => {
      receivedUrl = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          pathsvc: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: { type: 'path', name: 'apikey', value: 'mykey123' },
          },
        },
      });

      await request({ hostname: '127.0.0.1', port: proxy.port, path: '/pathsvc/v1/resource', method: 'GET' });
      assert.ok(receivedUrl.startsWith('/mykey123/v1/resource'), `Unexpected path: ${receivedUrl}`);
    } finally {
      await stopMock(mock);
    }
  });

  // ── route forwarding ─────────────────────────────────────────────────────

  test('strips service prefix from upstream path', async () => {
    let receivedUrl;
    const mock = await startMock((req, res) => {
      receivedUrl = req.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{}');
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          anthropic: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: null,
          },
        },
      });

      await request({ hostname: '127.0.0.1', port: proxy.port, path: '/anthropic/v1/messages', method: 'POST',
        headers: { 'Content-Type': 'application/json' } }, '{}');
      assert.strictEqual(receivedUrl, '/v1/messages');
    } finally {
      await stopMock(mock);
    }
  });

  test('unknown service returns 502', async () => {
    proxy.setSecrets({ version: 1, services: {} });
    const res = await request({ hostname: '127.0.0.1', port: proxy.port, path: '/unknown/v1/foo', method: 'GET' });
    assert.strictEqual(res.statusCode, 502);
    const body = JSON.parse(res.body);
    assert.ok(body.error.includes('unknown service'));
  });

  // ── SSE passthrough ───────────────────────────────────────────────────────

  test('SSE passthrough: content-type and events forwarded transparently', async () => {
    const mock = await startMock((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.write('data: {"id":1,"text":"hello"}\n\n');
      res.write('data: {"id":2,"text":"world"}\n\n');
      res.write('data: [DONE]\n\n');
      res.end();
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          streamsvc: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: null,
          },
        },
      });

      const res = await requestSSE({
        hostname: '127.0.0.1', port: proxy.port, path: '/streamsvc/v1/stream', method: 'GET',
      });
      assert.strictEqual(res.statusCode, 200);
      assert.ok(res.headers['content-type'].includes('text/event-stream'));
      assert.ok(res.body.includes('data: {"id":1,"text":"hello"}'));
      assert.ok(res.body.includes('data: {"id":2,"text":"world"}'));
      assert.ok(res.body.includes('data: [DONE]'));
    } finally {
      await stopMock(mock);
    }
  });

  test('SSE passthrough: method and body forwarded', async () => {
    let receivedMethod, receivedBody;
    const mock = await startMock((req, res) => {
      receivedMethod = req.method;
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => {
        receivedBody = Buffer.concat(chunks).toString();
        res.writeHead(200, { 'Content-Type': 'text/event-stream' });
        res.write('data: [DONE]\n\n');
        res.end();
      });
    });

    try {
      proxy.setSecrets({
        version: 1,
        services: {
          streamsvc: {
            upstream: `http://127.0.0.1:${mock.port}`,
            auth: null,
          },
        },
      });

      await requestSSE(
        { hostname: '127.0.0.1', port: proxy.port, path: '/streamsvc/v1/stream', method: 'POST',
          headers: { 'Content-Type': 'application/json' } },
        JSON.stringify({ stream: true }),
      );
      assert.strictEqual(receivedMethod, 'POST');
      assert.strictEqual(JSON.parse(receivedBody).stream, true);
    } finally {
      await stopMock(mock);
    }
  });

  // ── lock / setSecrets state transitions ───────────────────────────────────

  test('lock() clears secrets and sets locked=true', () => {
    proxy.setSecrets({ version: 1, services: { foo: {} } });
    assert.strictEqual(proxy.isLocked(), false);
    proxy.lock();
    assert.strictEqual(proxy.isLocked(), true);
  });

  test('setSecrets() sets locked=false', () => {
    assert.strictEqual(proxy.isLocked(), true);
    proxy.setSecrets({ version: 1, services: {} });
    assert.strictEqual(proxy.isLocked(), false);
  });
});
