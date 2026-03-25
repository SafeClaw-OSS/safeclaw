import http from 'node:http'
import https from 'node:https'
import { URL } from 'node:url'
import { readFileSync } from 'node:fs'

let PKG_VERSION = 'unknown'
try { PKG_VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version } catch {}

function lockedMessage(adminUrl) {
  // Strip protocol for display, keep full URL for link
  const display = adminUrl.replace(/^https?:\/\//, '')
  return `🔒 I can't respond — vault is locked.\n\nUnlock on SafeClaw to continue:\n[${display}](${adminUrl})`
}

// Parse request URL into { service, path, query }
// e.g. /anthropic/v1/messages?foo=bar → { service:'anthropic', path:'/v1/messages', query:'?foo=bar' }
export function parseRoute(reqUrl) {
  const qIdx = reqUrl.indexOf('?')
  const pathPart = qIdx >= 0 ? reqUrl.slice(0, qIdx) : reqUrl
  const queryPart = qIdx >= 0 ? reqUrl.slice(qIdx) : ''

  const parts = pathPart.split('/')
  if (parts.length < 2 || !parts[1]) return null

  const service = parts[1]
  const rest = '/' + parts.slice(2).join('/')

  return { service, path: rest, query: queryPart }
}

function sendLockedAnthropic(res, isStream, adminUrl) {
  const content = lockedMessage(adminUrl)
  const now = new Date().toISOString()
  const msgId = 'msg_locked_' + Math.floor(Date.now() / 1000)

  if (!isStream) {
    const body = JSON.stringify({
      id: msgId, type: 'message', role: 'assistant',
      content: [{ type: 'text', text: content }],
      model: 'claude-sonnet-4-20250514', stop_reason: 'end_turn', stop_sequence: null,
      usage: { input_tokens: 0, output_tokens: 0 },
    })
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
    res.end(body)
    return
  }

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })
  const sse = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)

  sse('message_start', { type: 'message_start', message: {
    id: msgId, type: 'message', role: 'assistant', content: [],
    model: 'claude-sonnet-4-20250514', stop_reason: null, stop_sequence: null,
    usage: { input_tokens: 0, output_tokens: 0 },
  }})
  sse('content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } })
  sse('content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: content } })
  sse('content_block_stop', { type: 'content_block_stop', index: 0 })
  sse('message_delta', { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 0 } })
  sse('message_stop', { type: 'message_stop' })
  res.end()
}

function sendLockedGemini(res, adminUrl) {
  const content = lockedMessage(adminUrl)
  // Gemini REST API response format (generateContent)
  const body = JSON.stringify({
    candidates: [{
      content: { parts: [{ text: content }], role: 'model' },
      finishReason: 'STOP', index: 0,
    }],
    usageMetadata: { promptTokenCount: 0, candidatesTokenCount: 0, totalTokenCount: 0 },
  })
  res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
  res.end(body)
}

function sendLockedResponsesApi(res, isStream, adminUrl) {
  const content = lockedMessage(adminUrl)
  const now = Math.floor(Date.now() / 1000)
  const respId = 'resp_locked_' + now
  const msgId = 'msg_locked_' + now

  const outputItem = {
    type: 'message', id: msgId, role: 'assistant', status: 'completed',
    content: [{ type: 'output_text', text: content, annotations: [] }],
  }
  const fullResponse = {
    id: respId, object: 'response', created_at: now, status: 'completed',
    model: 'gpt-4o', output: [outputItem],
    usage: { input_tokens: 0, output_tokens: 0, total_tokens: 0 },
  }

  if (!isStream) {
    const body = JSON.stringify(fullResponse)
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
    res.end(body)
    return
  }

  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' })

  const sse = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)

  // Minimal streaming lifecycle
  sse('response.created', { ...fullResponse, status: 'in_progress', output: [] })
  sse('response.in_progress', { ...fullResponse, status: 'in_progress', output: [] })
  sse('response.output_item.added', { type: 'response.output_item.added', output_index: 0, item: { ...outputItem, status: 'in_progress', content: [] } })
  sse('response.content_part.added', { type: 'response.content_part.added', output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } })
  sse('response.output_text.delta', { type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: content })
  sse('response.output_text.done', { type: 'response.output_text.done', output_index: 0, content_index: 0, text: content })
  sse('response.content_part.done', { type: 'response.content_part.done', output_index: 0, content_index: 0, part: { type: 'output_text', text: content, annotations: [] } })
  sse('response.output_item.done', { type: 'response.output_item.done', output_index: 0, item: outputItem })
  sse('response.completed', fullResponse)
  res.end()
}

function sendLockedResponse(res, isStream, adminUrl) {
  const content = lockedMessage(adminUrl)
  const body = {
    id: 'safeclaw-locked',
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: 'safeclaw-locked',
    choices: [{
      index: 0,
      message: { role: 'assistant', content },
      finish_reason: 'stop',
    }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
    // SafeClaw metadata for relay/consumer to render inline buttons
    safeclaw_locked: true,
    safeclaw_unlock_url: adminUrl,
    safeclaw_buttons: [[{ text: '🔓 Unlock SafeClaw', url: adminUrl }]],
  }

  if (isStream) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    })
    // Content chunk (delta format, matching OpenAI SSE spec)
    const now = Math.floor(Date.now() / 1000)
    const contentChunk = {
      id: 'chatcmpl-locked', object: 'chat.completion.chunk',
      created: now, model: 'gpt-4o',
      choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }],
    }
    res.write(`data: ${JSON.stringify(contentChunk)}\n\n`)
    // Final chunk
    const doneChunk = {
      id: 'chatcmpl-locked', object: 'chat.completion.chunk',
      created: now, model: 'gpt-4o',
      choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
    }
    res.write(`data: ${JSON.stringify(doneChunk)}\n\n`)
    res.write('data: [DONE]\n\n')
    res.end()
  } else {
    const bodyStr = JSON.stringify(body)
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(bodyStr),
    })
    res.end(bodyStr)
  }
}

export async function createProxy({ port, dataDir, serverPort }) {
  // SAFECLAW_ADMIN_URL: base URL for admin/console page (used in locked response message)
  const adminUrl = process.env.SAFECLAW_ADMIN_URL || `http://localhost:${serverPort}`

  let secrets = null
  let locked = true

  const isLocked = () => locked
  const setSecrets = (v) => { secrets = v; locked = false }
  const lock = () => { secrets = null; locked = true }

  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      const body = JSON.stringify({
        status: 'ok',
        locked: isLocked(),
        uptime: Math.floor(process.uptime()),
        version: PKG_VERSION,
      })
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
      res.end(body)
      return
    }

    console.log(`[proxy] ${req.method} ${req.url} locked=${isLocked()}`)

    const route = parseRoute(req.url)
    if (!route) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: 'invalid path' }))
      return
    }

    if (isLocked()) {
      const chunks = []
      req.on('data', c => chunks.push(c))
      req.on('end', () => {
        let isStream = false
        if (chunks.length > 0) {
          try {
            const parsed = JSON.parse(Buffer.concat(chunks).toString())
            isStream = !!parsed.stream
          } catch {}
        }
        // Route locked response to correct API format
        if (route.path.includes('/responses')) {
          sendLockedResponsesApi(res, isStream, adminUrl)
        } else if (route.service === 'anthropic' || route.path.includes('/messages')) {
          sendLockedAnthropic(res, isStream, adminUrl)
        } else if (route.service === 'google' || route.path.includes('generateContent')) {
          sendLockedGemini(res, adminUrl)
        } else {
          // OpenAI chat completions (also works for DeepSeek, Groq, etc.)
          sendLockedResponse(res, isStream, adminUrl)
        }
      })
      return
    }

    const serviceConfig = secrets?.services?.[route.service]
    if (!serviceConfig) {
      res.writeHead(502, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: `unknown service: ${route.service}` }))
      return
    }

    const { upstream, auth } = serviceConfig
    const upstreamUrl = new URL(upstream)
    const isHttps = upstreamUrl.protocol === 'https:'

    let upstreamPath = route.path
    if (auth?.type === 'path') {
      upstreamPath = '/' + auth.value + upstreamPath
    }

    let upstreamQuery = route.query
    if (auth?.type === 'query') {
      const sep = upstreamQuery ? '&' : '?'
      upstreamQuery += sep + encodeURIComponent(auth.name) + '=' + encodeURIComponent(auth.value)
    }

    const headers = {}
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.toLowerCase() === 'host') continue
      headers[k] = v
    }
    headers['host'] = upstreamUrl.host

    if (auth?.type === 'header') {
      const prefix = auth.prefix || ''
      headers[auth.name.toLowerCase()] = prefix ? prefix + ' ' + auth.value : auth.value
    }

    const options = {
      hostname: upstreamUrl.hostname,
      port: upstreamUrl.port || (isHttps ? 443 : 80),
      path: upstreamPath + upstreamQuery,
      method: req.method,
      headers,
    }

    const lib = isHttps ? https : http
    const proxyReq = lib.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers)
      proxyRes.pipe(res)
    })

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'upstream error', message: err.message }))
      }
    })

    req.pipe(proxyReq)
  })

  return new Promise((resolve, reject) => {
    const bindHost = process.env.SAFECLAW_PROXY_BIND || '127.0.0.1'
    server.listen(port, bindHost, () => {
      resolve({
        close: () => new Promise(r => server.close(r)),
        setSecrets,
        lock,
        isLocked,
        port: server.address().port,
      })
    })
    server.on('error', reject)
  })
}
