import crypto from 'node:crypto'
import http from 'node:http'

// ── Constants ─────────────────────────────────────────────────────────────────

export const TEST_HMAC_SECRET = 'test-hmac-secret-for-unit-tests'

export const SAMPLE_SECRETS = {
  version: 1,
  services: {
    anthropic: {
      upstream: 'https://api.anthropic.com',
      auth: { type: 'header', name: 'x-api-key', value: 'sk-ant-test' },
    },
  },
}

// ── WebAuthn mock helpers ─────────────────────────────────────────────────────

export async function makeP256Credential() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  )
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const x = Buffer.from(pubJwk.x, 'base64url').toString('base64')
  const y = Buffer.from(pubJwk.y, 'base64url').toString('base64')
  return { privateKey: keyPair.privateKey, x, y }
}

function rawToDer(raw) {
  function encodeInt(buf) {
    let start = 0
    while (start < buf.length - 1 && buf[start] === 0) start++
    buf = buf.slice(start)
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0x00]), buf])
    return buf
  }
  const rEnc = encodeInt(Buffer.from(raw).slice(0, 32))
  const sEnc = encodeInt(Buffer.from(raw).slice(32, 64))
  const len = 2 + rEnc.length + 2 + sEnc.length
  return Buffer.concat([
    Buffer.from([0x30, len, 0x02, rEnc.length]), rEnc,
    Buffer.from([0x02, sEnc.length]), sEnc,
  ])
}

export async function makeAssertion(privateKey, { rpId = 'localhost', origin = 'http://localhost', type = 'webauthn.get', upFlag = true } = {}) {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest()
  const flags = Buffer.from([upFlag ? 0x05 : 0x04])  // UP=1,UV=1 or UP=0,UV=1
  const signCount = Buffer.alloc(4)
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount])

  const clientDataJSON = Buffer.from(JSON.stringify({
    type,
    challenge: crypto.randomBytes(32).toString('base64url'),
    origin,
  }))

  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest()
  const signedData = Buffer.concat([authenticatorData, clientDataHash])

  const rawSig = Buffer.from(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, privateKey, signedData
  ))
  const derSig = rawToDer(rawSig)

  return {
    authenticatorData: authenticatorData.toString('base64'),
    clientDataJSON: clientDataJSON.toString('base64'),
    signature: derSig.toString('base64'),
  }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

export function httpRequest(port, method, path, body, { hmacSecret = TEST_HMAC_SECRET, skipHmac = false } = {}) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : null
    const headers = {
      'Content-Type': 'application/json',
      ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
    }
    if (method === 'POST' && bodyStr && hmacSecret && !skipHmac) {
      headers['x-relay-sig'] = crypto.createHmac('sha256', hmacSecret).update(bodyStr).digest('hex')
    }
    const req = http.request(
      { hostname: '127.0.0.1', port, path, method, headers },
      (res) => {
        const chunks = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => {
          resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) })
        })
      },
    )
    req.on('error', reject)
    if (bodyStr) req.write(bodyStr)
    req.end()
  })
}

// ── Server helpers ────────────────────────────────────────────────────────────

export function createMockProxy() {
  let secrets = null
  let locked = true
  return {
    setSecrets(v) { secrets = v; locked = false },
    lock() { secrets = null; locked = true },
    isLocked() { return locked },
    getSecrets() { return secrets },
  }
}

export function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = http.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
    srv.on('error', reject)
  })
}

export function makeNonce() {
  return crypto.randomBytes(32).toString('base64')
}
