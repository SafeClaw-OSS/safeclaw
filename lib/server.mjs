import http from 'node:http'
import crypto from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  loadOrCreateVmKeypair,
  deriveKEK,
  deriveResponseKey,
  encrypt,
  decrypt,
  generateDEK,
  wrapDEK,
  unwrapDEK,
  e2eDecrypt,
  zeroize,
} from './crypto.mjs'

// ── WebAuthn assertion verification ──────────────────────────────────────────

function derToParts(derSig) {
  let offset = 2
  const rLen = derSig[offset + 1]
  const r = derSig.subarray(offset + 2, offset + 2 + rLen)
  offset += 2 + rLen
  const sLen = derSig[offset + 1]
  const s = derSig.subarray(offset + 2, offset + 2 + sLen)

  const result = Buffer.alloc(64)
  r.copy(result, 32 - Math.min(r.length, 32), Math.max(r.length - 32, 0))
  s.copy(result, 64 - Math.min(s.length, 32), Math.max(s.length - 32, 0))
  return result
}

async function verifyP256Signature(x, y, authenticatorData, clientDataJSON, signature) {
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest()
  const signedData = Buffer.concat([authenticatorData, clientDataHash])

  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: Buffer.from(x, 'base64').toString('base64url'),
    y: Buffer.from(y, 'base64').toString('base64url'),
  }
  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']
  )

  const rawSig = derToParts(signature)
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, rawSig, signedData)
}

async function verifyAssertion(assertion, x, y) {
  if (!assertion || !assertion.authenticatorData || !assertion.clientDataJSON || !assertion.signature) {
    return false
  }
  if (!x || !y) return true
  try {
    const authData = Buffer.from(assertion.authenticatorData, 'base64')
    const clientData = Buffer.from(assertion.clientDataJSON, 'base64')
    const sig = Buffer.from(assertion.signature, 'base64')
    return await verifyP256Signature(x, y, authData, clientData, sig)
  } catch {
    return false
  }
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

function sendJSON(res, status, body) {
  const data = JSON.stringify(body)
  res.writeHead(status, { ...CORS_HEADERS, 'Content-Type': 'application/json' })
  res.end(data)
}

function readBody(req) {
  if (req._body !== undefined) return Promise.resolve(req._body.toString())
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', chunk => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks).toString()))
    req.on('error', reject)
  })
}

export async function createServer({ port, dataDir, proxy, hmacSecret } = {}) {
  const { pk: vmPk, sk: vmSk } = await loadOrCreateVmKeypair(dataDir)
  let serviceNames = []

  if (hmacSecret) console.log('[server] HMAC relay verification enabled')

  // Append-only nonce log — single-use client nonces, never deleted
  const noncesPath = join(dataDir, 'used_nonces.log')
  function checkAndRecordNonce(nonceB64) {
    const nonceHex = Buffer.from(nonceB64, 'base64').toString('hex')
    if (existsSync(noncesPath)) {
      const lines = readFileSync(noncesPath, 'utf8').split('\n').filter(Boolean)
      if (lines.includes(nonceHex)) return false
    }
    appendFileSync(noncesPath, nonceHex + '\n')
    return true
  }

  function readBodyBuffer(req) {
    if (req._body !== undefined) return Promise.resolve(req._body)
    return new Promise((resolve, reject) => {
      const chunks = []
      req.on('data', chunk => chunks.push(chunk))
      req.on('end', () => resolve(Buffer.concat(chunks)))
      req.on('error', reject)
    })
  }

  const publicDir = join(new URL('.', import.meta.url).pathname, '..', 'public')

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost')
    const pathname = url.pathname

    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS_HEADERS)
      res.end()
      return
    }

    // HMAC verification — only when hmacSecret is provided and request is POST
    if (hmacSecret && req.method === 'POST') {
      const sig = req.headers['x-relay-sig']
      if (!sig) {
        sendJSON(res, 401, { error: 'Missing relay signature' })
        return
      }
      const bodyBuf = await readBodyBuffer(req)
      const expected = crypto.createHmac('sha256', hmacSecret).update(bodyBuf).digest('hex')
      if (sig !== expected) {
        sendJSON(res, 403, { error: 'Invalid relay signature' })
        return
      }
      req._body = bodyBuf
    }

    try {
      // GET /vmPk — return server public key as JWK
      if (req.method === 'GET' && pathname === '/vmPk') {
        sendJSON(res, 200, { vmPk })
        return
      }

      // GET /health
      if (req.method === 'GET' && pathname === '/health') {
        sendJSON(res, 200, { status: 'ok' })
        return
      }

      // GET /admin/status
      if (req.method === 'GET' && pathname === '/admin/status') {
        let passkeys = []
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (existsSync(passkeysPath)) {
          passkeys = Object.keys(JSON.parse(readFileSync(passkeysPath, 'utf8')))
        }
        sendJSON(res, 200, {
          locked: proxy.isLocked(),
          uptime: process.uptime(),
          services: serviceNames,
          passkeys,
        })
        return
      }

      // POST /admin/lock
      if (req.method === 'POST' && pathname === '/admin/lock') {
        proxy.lock()
        serviceNames = []
        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /setup
      if (req.method === 'POST' && pathname === '/setup') {
        const bodyStr = await readBody(req)
        const { payload, assertions } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed0
        try { parsed0 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { passkeys, secrets, userKeys, nonce } = parsed0

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        for (let i = 0; i < passkeys.length; i++) {
          const { x, y } = passkeys[i]
          const assertion = assertions?.[i]
          if (!await verifyAssertion(assertion, x, y)) {
            sendJSON(res, 401, { error: 'Assertion verification failed' })
            return
          }
        }

        const dek = generateDEK()
        writeFileSync(join(dataDir, 'vault.enc'), await encrypt(dek, Buffer.from(JSON.stringify(secrets))))

        const passkeysMap = {}
        for (let i = 0; i < passkeys.length; i++) {
          const { credentialId, x, y, deviceName } = passkeys[i]
          passkeysMap[credentialId] = { x, y, deviceName, createdAt: Date.now() }

          const userKeyBuf = Buffer.from(userKeys[i], 'base64')
          const kek = await deriveKEK(userKeyBuf, vmSk)
          writeFileSync(join(dataDir, `wrapped_dek_${credentialId}.bin`), await wrapDEK(dek, kek))
          zeroize(userKeyBuf, kek)
        }

        writeFileSync(join(dataDir, 'passkeys.json'), JSON.stringify(passkeysMap))
        zeroize(dek)

        proxy.setSecrets(secrets)
        serviceNames = Object.keys(secrets.services || {})

        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /unlock
      if (req.method === 'POST' && pathname === '/unlock') {
        const bodyStr = await readBody(req)
        const { payload, credentialId, assertion } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed1
        try { parsed1 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce } = parsed1

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))
        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        const wrappedPath = join(dataDir, `wrapped_dek_${credentialId}.bin`)
        if (!existsSync(wrappedPath)) {
          sendJSON(res, 401, { error: 'No wrapped DEK for credential' })
          return
        }

        const userKeyBuf = Buffer.from(userKeyB64, 'base64')
        const kek = await deriveKEK(userKeyBuf, vmSk)
        const dek = await unwrapDEK(readFileSync(wrappedPath), kek)

        const secretsBuf = await decrypt(dek, readFileSync(join(dataDir, 'vault.enc')))
        const secrets = JSON.parse(secretsBuf.toString())
        zeroize(secretsBuf)

        proxy.setSecrets(secrets)
        serviceNames = Object.keys(secrets.services || {})

        zeroize(userKeyBuf, kek, dek)

        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /admin/credentials — decrypt and return vault contents, encrypted with response key
      if (req.method === 'POST' && pathname === '/admin/credentials') {
        const bodyStr = await readBody(req)
        const { payload, assertion } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed2
        try { parsed2 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce, credentialId } = parsed2

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))
        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        const wrappedPath = join(dataDir, `wrapped_dek_${credentialId}.bin`)
        if (!existsSync(wrappedPath)) {
          sendJSON(res, 401, { error: 'No wrapped DEK for credential' })
          return
        }

        const userKeyBuf = Buffer.from(userKeyB64, 'base64')
        const nonceBuf = Buffer.from(nonce, 'base64')
        const kek = await deriveKEK(userKeyBuf, vmSk)
        const dek = await unwrapDEK(readFileSync(wrappedPath), kek)
        const secretsBuf = await decrypt(dek, readFileSync(join(dataDir, 'vault.enc')))

        const responseKey = await deriveResponseKey(userKeyBuf, nonceBuf)
        const sealed = await encrypt(responseKey, secretsBuf)

        zeroize(userKeyBuf, nonceBuf, kek, dek, responseKey, secretsBuf)

        sendJSON(res, 200, { sealed: sealed.toString('base64') })
        return
      }

      // POST /admin/update-secrets — re-encrypt vault with new secrets
      if (req.method === 'POST' && pathname === '/admin/update-secrets') {
        const bodyStr = await readBody(req)
        const { payload, assertion } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed3
        try { parsed3 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce, credentialId, newSecrets } = parsed3

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))
        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        const wrappedPath = join(dataDir, `wrapped_dek_${credentialId}.bin`)
        if (!existsSync(wrappedPath)) {
          sendJSON(res, 401, { error: 'No wrapped DEK for credential' })
          return
        }

        const userKeyBuf = Buffer.from(userKeyB64, 'base64')
        const kek = await deriveKEK(userKeyBuf, vmSk)
        const dek = await unwrapDEK(readFileSync(wrappedPath), kek)

        writeFileSync(join(dataDir, 'vault.enc'), await encrypt(dek, Buffer.from(JSON.stringify(newSecrets))))
        proxy.setSecrets(newSecrets)
        serviceNames = Object.keys(newSecrets.services || {})

        zeroize(userKeyBuf, kek, dek)

        sendJSON(res, 200, { ok: true })
        return
      }

      // Static file serving (setup/unlock/admin pages)
      if (pathname === '/' || pathname.endsWith('.html')) {
        const relative = pathname === '/' ? 'index.html' : pathname.slice(1)
        const filePath = join(publicDir, relative)

        if (!filePath.startsWith(publicDir + '/') && filePath !== publicDir) {
          sendJSON(res, 403, { error: 'Forbidden' })
          return
        }

        if (!existsSync(filePath)) {
          sendJSON(res, 404, { error: 'Not found' })
          return
        }

        const content = readFileSync(filePath)
        const ext = filePath.split('.').pop()
        const contentType = ext === 'html' ? 'text/html'
          : ext === 'js' ? 'application/javascript'
          : ext === 'css' ? 'text/css'
          : 'application/octet-stream'
        res.writeHead(200, { ...CORS_HEADERS, 'Content-Type': contentType, 'Cache-Control': 'no-cache' })
        res.end(content)
        return
      }

      sendJSON(res, 404, { error: 'Not found' })
    } catch (err) {
      console.error('[server] error:', err)
      sendJSON(res, 500, { error: err.message })
    }
  })

  return new Promise((resolve, reject) => {
    server.listen(port, () => resolve(server))
    server.on('error', reject)
  })
}
