import { umask } from 'node:process'
umask(0o077)

import http from 'node:http'
import crypto from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, appendFileSync, unlinkSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'))

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

async function verifyAssertion(assertion, x, y, expectedOrigin, rpId) {
  if (!assertion || !assertion.authenticatorData || !assertion.clientDataJSON || !assertion.signature) {
    return false
  }
  // Fix: return false when x or y is null/falsy (previously returned true, bypassing verification)
  if (!x || !y) return false
  try {
    const authData = Buffer.from(assertion.authenticatorData, 'base64')
    const clientData = Buffer.from(assertion.clientDataJSON, 'base64')
    const sig = Buffer.from(assertion.signature, 'base64')

    // Check clientDataJSON.type
    const clientDataObj = JSON.parse(clientData.toString())
    if (clientDataObj.type !== 'webauthn.get') return false

    // Check clientDataJSON.origin
    if (clientDataObj.origin !== expectedOrigin) return false

    // Check rpIdHash (first 32 bytes of authenticatorData) matches SHA-256(rpId)
    const expectedRpIdHash = crypto.createHash('sha256').update(rpId).digest()
    const actualRpIdHash = authData.subarray(0, 32)
    if (actualRpIdHash.length !== expectedRpIdHash.length) return false
    if (!crypto.timingSafeEqual(expectedRpIdHash, actualRpIdHash)) return false

    // Check UP (User Present) flag — bit 0 of flags byte at authenticatorData offset 32
    const flags = authData[32]
    if (!(flags & 0x01)) return false

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

export async function createServer({ port, dataDir, proxy, expectedOrigin, rpId, exitFn, rateLimit = 20, onSetup } = {}) {
  if (!expectedOrigin || !rpId) {
    throw new Error('[safeclaw] expectedOrigin and rpId are required. Set SAFECLAW_ORIGIN and SAFECLAW_RP_ID environment variables.')
  }
  exitFn = exitFn || ((code) => process.exit(code))

  const { pk: vmPk, sk: vmSk } = await loadOrCreateVmKeypair(dataDir)
  let serviceNames = []

  // Per-IP rate limit (requests per minute). 0 = disabled.
  const rateLimitPerMin = rateLimit
  const rateBuckets = new Map() // ip → { count, resetAt }
  function checkRateLimit(ip) {
    if (rateLimitPerMin <= 0) return true
    const now = Date.now()
    let bucket = rateBuckets.get(ip)
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + 60_000 }
      rateBuckets.set(ip, bucket)
    }
    bucket.count++
    return bucket.count <= rateLimitPerMin
  }
  // Periodic cleanup of stale buckets (every 5 min)
  const cleanupInterval = setInterval(() => {
    const now = Date.now()
    for (const [ip, bucket] of rateBuckets) {
      if (now >= bucket.resetAt) rateBuckets.delete(ip)
    }
  }, 300_000)
  cleanupInterval.unref()

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

  const publicDir = join(new URL('.', import.meta.url).pathname, '..', 'public')

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost')
    const pathname = url.pathname

    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS_HEADERS)
      res.end()
      return
    }

    // Per-IP rate limit for POST requests
    if (req.method === 'POST') {
      const remote = req.socket.remoteAddress || '127.0.0.1'
      if (!checkRateLimit(remote)) {
        sendJSON(res, 429, { error: 'Rate limit exceeded' })
        return
      }
    }

    try {
      // GET /vmPk — return server public key as JWK
      if (req.method === 'GET' && pathname === '/vmPk') {
        sendJSON(res, 200, { vmPk })
        return
      }

      // GET /health
      if (req.method === 'GET' && pathname === '/health') {
        sendJSON(res, 200, {
          status: 'ok',
          locked: proxy.isLocked(),
          uptime: Math.floor(process.uptime()),
          version: pkg.version,
        })
        return
      }

      // POST /admin/status — returns basic status without auth, full status with auth
      if (req.method === 'POST' && pathname === '/admin/status') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        const passkeysData = existsSync(passkeysPath)
          ? JSON.parse(readFileSync(passkeysPath, 'utf8'))
          : {}

        const bodyStr = await readBody(req)

        // Empty body → return basic non-sensitive status
        if (!bodyStr || bodyStr.trim() === '' || bodyStr.trim() === '{}') {
          sendJSON(res, 200, {
            locked: proxy.isLocked(),
            uptime: process.uptime(),
            services: serviceNames,
            passkeys: Object.keys(passkeysData).map(id => ({ id, deviceName: passkeysData[id].deviceName })),
          })
          return
        }

        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { nonce, credentialId, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        sendJSON(res, 200, {
          locked: proxy.isLocked(),
          uptime: process.uptime(),
          services: serviceNames,
          passkeys: Object.keys(passkeysData),
        })
        return
      }

      // POST /admin/lock — requires passkey assertion
      if (req.method === 'POST' && pathname === '/admin/lock') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))

        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { nonce, credentialId, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        proxy.lock()
        serviceNames = []
        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /setup
      if (req.method === 'POST' && pathname === '/setup') {
        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed0
        try { parsed0 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { passkeys, secrets: rawSecrets, userKeys, nonce, assertions, existingCredentialId, existingAssertion } = parsed0

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        // If vault already exists, require existing passkey auth before overwrite
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (existsSync(passkeysPath)) {
          const existingPasskeys = JSON.parse(readFileSync(passkeysPath, 'utf8'))
          if (!existingCredentialId || !existingPasskeys[existingCredentialId]) {
            sendJSON(res, 401, { error: 'Vault exists: existing passkey auth required to overwrite' })
            return
          }
          const { x: ex, y: ey } = existingPasskeys[existingCredentialId]
          if (!await verifyAssertion(existingAssertion, ex, ey, expectedOrigin, rpId)) {
            sendJSON(res, 401, { error: 'Existing passkey assertion verification failed' })
            return
          }
        }

        for (let i = 0; i < passkeys.length; i++) {
          const { x, y } = passkeys[i]
          const assertion = assertions?.[i]
          if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
            sendJSON(res, 401, { error: 'Assertion verification failed' })
            return
          }
        }

        // onSetup hook: let caller transform secrets before vault write
        let secrets = rawSecrets
        if (onSetup) {
          const hookResult = await onSetup({ payload: parsed0, secrets: rawSecrets })
          if (hookResult && hookResult.secrets !== undefined) secrets = hookResult.secrets
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
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed1
        try { parsed1 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce, credentialId, assertion } = parsed1

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
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
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
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed2
        try { parsed2 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce, credentialId, assertion } = parsed2

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
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
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
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed3
        try { parsed3 = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { userKey: userKeyB64, nonce, credentialId, newSecrets, assertion } = parsed3

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
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
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

      // POST /admin/add-passkey — add new passkey credential; requires existing passkey assertion
      if (req.method === 'POST' && pathname === '/admin/add-passkey') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))

        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { credentialId, userKey: userKeyB64, nonce, newPasskey, newUserKey: newUserKeyB64, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
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

        const newUserKeyBuf = Buffer.from(newUserKeyB64, 'base64')
        const newKek = await deriveKEK(newUserKeyBuf, vmSk)
        writeFileSync(join(dataDir, `wrapped_dek_${newPasskey.credentialId}.bin`), await wrapDEK(dek, newKek))

        passkeysData[newPasskey.credentialId] = {
          x: newPasskey.x,
          y: newPasskey.y,
          deviceName: newPasskey.deviceName,
          createdAt: Date.now(),
        }
        writeFileSync(passkeysPath, JSON.stringify(passkeysData))

        zeroize(userKeyBuf, kek, dek, newUserKeyBuf, newKek)

        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /admin/remove-passkey — remove a passkey credential; cannot remove last passkey
      if (req.method === 'POST' && pathname === '/admin/remove-passkey') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))

        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { credentialId, nonce, removeCredentialId, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        if (!passkeysData[removeCredentialId]) {
          sendJSON(res, 400, { error: 'Credential to remove not found' })
          return
        }

        if (Object.keys(passkeysData).length <= 1) {
          sendJSON(res, 400, { error: 'Cannot remove the last passkey' })
          return
        }

        delete passkeysData[removeCredentialId]
        writeFileSync(passkeysPath, JSON.stringify(passkeysData))

        const wrappedPath = join(dataDir, `wrapped_dek_${removeCredentialId}.bin`)
        if (existsSync(wrappedPath)) unlinkSync(wrappedPath)

        sendJSON(res, 200, { ok: true })
        return
      }

      // POST /admin/restart — lock and exit with code 0 (systemd will restart)
      if (req.method === 'POST' && pathname === '/admin/restart') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))

        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { nonce, credentialId, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        proxy.lock()
        serviceNames = []
        sendJSON(res, 200, { ok: true })
        exitFn(0)
        return
      }

      // POST /admin/shutdown — lock and exit with code 1
      if (req.method === 'POST' && pathname === '/admin/shutdown') {
        const passkeysPath = join(dataDir, 'passkeys.json')
        if (!existsSync(passkeysPath)) {
          sendJSON(res, 401, { error: 'Not set up' })
          return
        }
        const passkeysData = JSON.parse(readFileSync(passkeysPath, 'utf8'))

        const bodyStr = await readBody(req)
        const { payload } = JSON.parse(bodyStr)

        const ciphertext = Buffer.from(payload, 'base64')
        const plaintext = await e2eDecrypt(ciphertext, vmPk, vmSk)
        let parsed
        try { parsed = JSON.parse(plaintext.toString()) } finally { zeroize(plaintext) }
        const { nonce, credentialId, assertion } = parsed

        if (!checkAndRecordNonce(nonce)) {
          sendJSON(res, 400, { error: 'Nonce already used' })
          return
        }

        if (!passkeysData[credentialId]) {
          sendJSON(res, 401, { error: 'Unknown credential' })
          return
        }

        const { x, y } = passkeysData[credentialId]
        if (!await verifyAssertion(assertion, x, y, expectedOrigin, rpId)) {
          sendJSON(res, 401, { error: 'Assertion verification failed' })
          return
        }

        proxy.lock()
        serviceNames = []
        sendJSON(res, 200, { ok: true })
        exitFn(1)
        return
      }

      // Static file serving (setup/unlock/admin pages)
      // Support clean URLs: /setup → setup.html, /admin → admin.html, etc.
      const CLEAN_PAGES = { '/setup': 'setup.html', '/unlock': 'unlock.html', '/admin': 'admin.html' };
      if (pathname === '/' || pathname.endsWith('.html') || CLEAN_PAGES[pathname]) {
        const relative = pathname === '/' ? 'index.html'
          : CLEAN_PAGES[pathname] || pathname.slice(1)
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
