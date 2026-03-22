import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'

import { generateDEK, e2eEncrypt, deriveResponseKey, decrypt } from '../lib/crypto.mjs'
import { createServer } from '../lib/server.mjs'

// ── WebAuthn assertion mock helpers ───────────────────────────────────────────

// Generate a real P-256 keypair; returns { privateKey, x, y } where x/y are base64
async function makeP256Credential() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  // JWK x/y are base64url; convert to regular base64 (our storage format)
  const x = Buffer.from(pubJwk.x, 'base64url').toString('base64')
  const y = Buffer.from(pubJwk.y, 'base64url').toString('base64')
  return { privateKey: keyPair.privateKey, x, y }
}

// Convert raw r||s (64 bytes) ECDSA signature to DER
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
    Buffer.from([0x30, len, 0x02, rEnc.length]),
    rEnc,
    Buffer.from([0x02, sEnc.length]),
    sEnc,
  ])
}

// Create a mock WebAuthn assertion (authenticatorData + clientDataJSON + DER signature)
async function makeAssertion(privateKey) {
  const rpIdHash = crypto.createHash('sha256').update('localhost').digest()
  const flags = Buffer.from([0x05])   // UP=1, UV=1
  const signCount = Buffer.alloc(4)
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount])

  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get',
    challenge: crypto.randomBytes(32).toString('base64url'),
    origin: 'http://localhost',
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

// ── Helpers ───────────────────────────────────────────────────────────────────

function httpRequest(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : null
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {}),
        },
      },
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

function createMockProxy() {
  let secrets = null
  let locked = true
  return {
    setSecrets(v) { secrets = v; locked = false },
    lock() { secrets = null; locked = true },
    isLocked() { return locked },
    getSecrets() { return secrets },
  }
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = http.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
    srv.on('error', reject)
  })
}

function makeNonce() {
  return crypto.randomBytes(32).toString('base64')
}

const SAMPLE_SECRETS = {
  version: 1,
  services: {
    anthropic: {
      upstream: 'https://api.anthropic.com',
      auth: { type: 'header', name: 'x-api-key', value: 'sk-ant-test' },
    },
  },
}

// ── GET /vmPk ─────────────────────────────────────────────────────────────────

test('GET /vmPk returns vmPk JWK', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { status, body } = await httpRequest(port, 'GET', '/vmPk')
  assert.strictEqual(status, 200)
  assert.ok(typeof body.vmPk === 'object', 'vmPk should be a JWK object')
  assert.strictEqual(body.vmPk.kty, 'EC', 'vmPk should be an EC key')
  assert.strictEqual(body.vmPk.crv, 'P-256', 'vmPk should use P-256 curve')
  assert.ok(body.vmPk.x, 'vmPk should have x coordinate')
  assert.ok(body.vmPk.y, 'vmPk should have y coordinate')
  assert.strictEqual(body.vmPk.d, undefined, 'vmPk should not contain private key')
})

// ── GET /health ───────────────────────────────────────────────────────────────

test('GET /health returns ok', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { status, body } = await httpRequest(port, 'GET', '/health')
  assert.strictEqual(status, 200)
  assert.strictEqual(body.status, 'ok')
})

// ── POST /setup ───────────────────────────────────────────────────────────────

test('POST /setup creates vault.enc, wrapped DEK, passkeys.json and unlocks proxy', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-setup-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'TestPhone' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }

  const assertion = await makeAssertion(cred.privateKey)
  const encrypted = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/setup', {
    payload: encrypted.toString('base64'),
    assertions: [assertion],
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.ok(existsSync(join(dir, 'vault.enc')), 'vault.enc should exist')
  assert.ok(existsSync(join(dir, 'passkeys.json')), 'passkeys.json should exist')
  assert.ok(existsSync(join(dir, `wrapped_dek_${credentialId}.bin`)), 'wrapped DEK should exist')
  assert.strictEqual(proxy.isLocked(), false)
})

// ── POST /unlock ──────────────────────────────────────────────────────────────

test('POST /unlock decrypts vault and unlocks proxy', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-unlock-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  // Setup first
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'Laptop' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })

  // Lock manually
  proxy.lock()
  assert.strictEqual(proxy.isLocked(), true)

  // Unlock
  const unlockPayload = { userKey: userKey.toString('base64'), nonce: makeNonce() }
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify(unlockPayload)), vmPk)
  const unlockAssertion = await makeAssertion(cred.privateKey)
  const { status, body } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
    credentialId,
    assertion: unlockAssertion,
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.isLocked(), false)
})

// ── GET /admin/status ─────────────────────────────────────────────────────────

test('GET /admin/status shows correct state before and after setup', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  // Before setup: locked, no passkeys
  const { status: s1, body: b1 } = await httpRequest(port, 'GET', '/admin/status')
  assert.strictEqual(s1, 200)
  assert.strictEqual(b1.locked, true)
  assert.deepStrictEqual(b1.passkeys, [])
  assert.ok(typeof b1.uptime === 'number')

  // Setup
  const credentialId = 'cred-status-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })

  // After setup: unlocked, passkeys and services populated
  const { body: b2 } = await httpRequest(port, 'GET', '/admin/status')
  assert.strictEqual(b2.locked, false)
  assert.deepStrictEqual(b2.passkeys, [credentialId])
  assert.deepStrictEqual(b2.services, ['anthropic'])
})

// ── Nonce replay prevention ───────────────────────────────────────────────────

test('POST /setup rejects replayed nonce', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const nonce = makeNonce()
  const userKey = generateDEK()
  const cred1 = await makeP256Credential()
  const cred2 = await makeP256Credential()

  // First setup — should succeed
  const setupPayload1 = {
    passkeys: [{ credentialId: 'cred-replay-001', x: cred1.x, y: cred1.y, deviceName: 'Dev' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce,
  }
  const enc1 = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload1)), vmPk)
  const assertion1 = await makeAssertion(cred1.privateKey)
  const first = await httpRequest(port, 'POST', '/setup', {
    payload: enc1.toString('base64'),
    assertions: [assertion1],
  })
  assert.strictEqual(first.status, 200)

  // Second setup with same nonce — should be rejected
  const setupPayload2 = {
    passkeys: [{ credentialId: 'cred-replay-002', x: cred2.x, y: cred2.y, deviceName: 'Dev2' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce,
  }
  const enc2 = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload2)), vmPk)
  const assertion2 = await makeAssertion(cred2.privateKey)
  const { status, body } = await httpRequest(port, 'POST', '/setup', {
    payload: enc2.toString('base64'),
    assertions: [assertion2],
  })

  assert.strictEqual(status, 400)
  assert.ok(body.error, 'should return an error message')
})

test('POST /unlock rejects replayed nonce', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-unlock-replay'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  // Setup with a fresh nonce
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'Dev' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })
  proxy.lock()

  // First unlock — should succeed
  const nonce = makeNonce()
  const unlockPayload1 = { userKey: userKey.toString('base64'), nonce }
  const unlockEnc1 = await e2eEncrypt(Buffer.from(JSON.stringify(unlockPayload1)), vmPk)
  const unlockAssertion1 = await makeAssertion(cred.privateKey)
  const first = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc1.toString('base64'),
    credentialId,
    assertion: unlockAssertion1,
  })
  assert.strictEqual(first.status, 200)

  proxy.lock()

  // Second unlock with same nonce — should be rejected
  const unlockPayload2 = { userKey: userKey.toString('base64'), nonce }
  const unlockEnc2 = await e2eEncrypt(Buffer.from(JSON.stringify(unlockPayload2)), vmPk)
  const unlockAssertion2 = await makeAssertion(cred.privateKey)
  const { status, body } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc2.toString('base64'),
    credentialId,
    assertion: unlockAssertion2,
  })

  assert.strictEqual(status, 400)
  assert.ok(body.error, 'should return an error message')
})

// ── POST /admin/credentials ───────────────────────────────────────────────────

test('POST /admin/credentials returns response-key-encrypted vault contents', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-view-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  // Setup
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })

  // View credentials
  const nonce = crypto.randomBytes(32)
  const viewPayload = { userKey: userKey.toString('base64'), nonce: nonce.toString('base64'), credentialId }
  const viewEnc = await e2eEncrypt(Buffer.from(JSON.stringify(viewPayload)), vmPk)
  const viewAssertion = await makeAssertion(cred.privateKey)
  const { status, body } = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: viewEnc.toString('base64'),
    assertion: viewAssertion,
  })

  assert.strictEqual(status, 200)
  assert.ok(typeof body.sealed === 'string', 'should return sealed base64 string')

  // Verify we can decrypt the response with the derived key
  const responseKey = await deriveResponseKey(userKey, nonce)
  const sealedBuf = Buffer.from(body.sealed, 'base64')
  const secretsBuf = await decrypt(responseKey, sealedBuf)
  const secrets = JSON.parse(secretsBuf.toString())
  assert.deepStrictEqual(secrets, SAMPLE_SECRETS)
})

test('POST /admin/credentials rejects replayed nonce', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-view-replay'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })

  const nonce = crypto.randomBytes(32)
  const viewPayload = { userKey: userKey.toString('base64'), nonce: nonce.toString('base64'), credentialId }

  const enc1 = await e2eEncrypt(Buffer.from(JSON.stringify(viewPayload)), vmPk)
  const viewAssertion1 = await makeAssertion(cred.privateKey)
  const first = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: enc1.toString('base64'),
    assertion: viewAssertion1,
  })
  assert.strictEqual(first.status, 200)

  const enc2 = await e2eEncrypt(Buffer.from(JSON.stringify(viewPayload)), vmPk)
  const viewAssertion2 = await makeAssertion(cred.privateKey)
  const { status, body: body2 } = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: enc2.toString('base64'),
    assertion: viewAssertion2,
  })
  assert.strictEqual(status, 400)
  assert.ok(body2.error)
})

// ── POST /admin/update-secrets ────────────────────────────────────────────────

test('POST /admin/update-secrets re-encrypts vault with new secrets', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')

  const credentialId = 'cred-update-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const setupAssertion = await makeAssertion(cred.privateKey)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
    assertions: [setupAssertion],
  })

  const newSecrets = {
    version: 1,
    services: {
      anthropic: {
        upstream: 'https://api.anthropic.com',
        auth: { type: 'header', name: 'x-api-key', value: 'sk-ant-updated' },
      },
    },
  }

  const updatePayload = {
    userKey: userKey.toString('base64'),
    nonce: makeNonce(),
    credentialId,
    newSecrets,
  }
  const updateEnc = await e2eEncrypt(Buffer.from(JSON.stringify(updatePayload)), vmPk)
  const updateAssertion = await makeAssertion(cred.privateKey)
  const { status, body } = await httpRequest(port, 'POST', '/admin/update-secrets', {
    payload: updateEnc.toString('base64'),
    assertion: updateAssertion,
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.getSecrets().services.anthropic.auth.value, 'sk-ant-updated')

  // Verify vault.enc was re-encrypted (unlock should get new secrets)
  proxy.lock()
  const unlockPayload = { userKey: userKey.toString('base64'), nonce: makeNonce() }
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify(unlockPayload)), vmPk)
  const unlockAssertion = await makeAssertion(cred.privateKey)
  const unlockRes = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
    credentialId,
    assertion: unlockAssertion,
  })
  assert.strictEqual(unlockRes.status, 200)
  assert.strictEqual(proxy.getSecrets().services.anthropic.auth.value, 'sk-ant-updated')
})
