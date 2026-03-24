import http from 'node:http'
import https from 'node:https'
import { URL } from 'node:url'

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

function sendLockedResponse(res, isStream, unlockUrl) {
  const content = `🔒 SafeClaw is locked. Tap the button below to unlock.`
  const body = {
    id: 'safeclaw-locked',
    object: 'chat.completion',
    choices: [{
      message: { role: 'assistant', content },
      finish_reason: 'stop',
    }],
    // SafeClaw metadata for relay/consumer to render inline buttons
    safeclaw_locked: true,
    safeclaw_unlock_url: unlockUrl,
    safeclaw_buttons: [[{ text: '🔓 Unlock SafeClaw', url: unlockUrl }]],
  }

  if (isStream) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    })
    const chunk = { ...body, object: 'chat.completion.chunk' }
    res.write(`data: ${JSON.stringify(chunk)}\n\n`)
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
  // Unlock URL: SAFECLAW_URL env var or default to localhost
  // SAFECLAW_INSTANCE_ID: optional instance ID for multi-VM routing (/u/:id/ prefix)
  const baseUrl = process.env.SAFECLAW_URL || `http://localhost:${serverPort}`
  const instanceId = process.env.SAFECLAW_INSTANCE_ID
  const unlockUrl = instanceId
    ? `${baseUrl}/u/${encodeURIComponent(instanceId)}/unlock`
    : `${baseUrl}/unlock`

  let secrets = null
  let locked = true

  const isLocked = () => locked
  const setSecrets = (v) => { secrets = v; locked = false }
  const lock = () => { secrets = null; locked = true }

  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      const body = JSON.stringify({ status: 'ok', locked: isLocked() })
      res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) })
      res.end(body)
      return
    }

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
        sendLockedResponse(res, isStream, unlockUrl)
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
    server.listen(port, '127.0.0.1', () => {
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
