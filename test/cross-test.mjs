#!/usr/bin/env node
// Cross-test: JS crypto → Rust server
// Verifies wire compatibility between safeclaw-client.js crypto and Rust backend.

import { execSync, spawn } from 'node:child_process'
import { readFileSync, writeFileSync, existsSync, rmSync, mkdirSync, chmodSync } from 'node:fs'
import { join } from 'node:path'
import crypto from 'node:crypto'
import { strict as assert } from 'node:assert'

const RUST_BIN = join(import.meta.dirname, '..', 'target', 'release', 'safeclaw')
const DATA_DIR = join(import.meta.dirname, '..', '.cross-test-data')
const SERVER_PORT = 23394
const PROXY_PORT = 23395
const ORIGIN = 'https://test.safeclaw.dev'
const RP_ID = 'test.safeclaw.dev'

// ── JS crypto helpers (matching safeclaw-client.js + lib/crypto.mjs) ──────

function toBase64(buf) {
  return Buffer.from(buf).toString('base64')
}

function toBase64url(buf) {
  return Buffer.from(buf).toString('base64url')
}

async function e2eEncrypt(plaintext, serverPkJwk) {
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  )
  const serverPub = await crypto.subtle.importKey(
    'jwk', serverPkJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPub }, ephemeral.privateKey, 256
  )
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits'])
  const aesKeyBits = await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256',
    salt: new Uint8Array(32),
    info: new TextEncoder().encode('safeclaw-e2e'),
  }, hkdfKey, 256)
  const aesKey = await crypto.subtle.importKey(
    'raw', aesKeyBits, { name: 'AES-GCM' }, false, ['encrypt']
  )

  const iv = crypto.randomBytes(12)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext)
  const epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey)

  const wire = JSON.stringify({
    epk, iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)),
  })
  return Buffer.from(wire)
}

async function deriveUserKey() {
  // Simulate PRF output → HKDF normalize
  const prfOutput = crypto.randomBytes(32)
  const keyMaterial = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits'])
  const derived = await crypto.subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256',
    salt: new Uint8Array(32),
    info: new TextEncoder().encode('safeclaw-user-key'),
  }, keyMaterial, 256)
  return Buffer.from(derived)
}

// Fake WebAuthn assertion — we'll sign with a known P-256 key
async function createFakePasskey() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  )
  const pubJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  // Convert base64url to standard base64 for storage (matching browser behavior)
  const x = Buffer.from(pubJwk.x, 'base64url').toString('base64')
  const y = Buffer.from(pubJwk.y, 'base64url').toString('base64')
  const credentialId = toBase64(crypto.randomBytes(32))

  return { keyPair, x, y, credentialId }
}

// Convert P1363 raw signature (r||s, 64 bytes) to DER encoding
// WebAuthn returns DER, but Node.js crypto.subtle.sign returns P1363
function p1363ToDer(p1363) {
  const r = p1363.subarray(0, 32)
  const s = p1363.subarray(32, 64)

  function intToDer(intBytes) {
    // Strip leading zeros, but keep at least 1 byte
    let start = 0
    while (start < intBytes.length - 1 && intBytes[start] === 0) start++
    let trimmed = intBytes.subarray(start)
    // Add leading 0x00 if high bit is set (DER sign encoding)
    if (trimmed[0] & 0x80) {
      trimmed = Buffer.concat([Buffer.from([0x00]), trimmed])
    }
    return Buffer.concat([Buffer.from([0x02, trimmed.length]), trimmed])
  }

  const rDer = intToDer(r)
  const sDer = intToDer(s)
  const inner = Buffer.concat([rDer, sDer])
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner])
}

async function createFakeAssertion(privateKey, origin, rpId) {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest()
  // flags: UP (0x01) + UV (0x04) = 0x05
  const flags = Buffer.from([0x05])
  // signCount: 4 bytes
  const signCount = Buffer.alloc(4)
  const authenticatorData = Buffer.concat([rpIdHash, flags, signCount])

  const clientDataObj = {
    type: 'webauthn.get',
    challenge: toBase64url(crypto.randomBytes(32)),
    origin,
  }
  const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj))
  const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest()
  const signedData = Buffer.concat([authenticatorData, clientDataHash])

  // Node.js crypto.subtle.sign returns P1363 (r||s), but WebAuthn returns DER
  const p1363Sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    signedData
  )
  const derSig = p1363ToDer(Buffer.from(p1363Sig))

  return {
    authenticatorData: toBase64(authenticatorData),
    clientDataJSON: toBase64(clientDataJSON),
    signature: toBase64(derSig),
  }
}

async function makeAuthPayload(serverPk, innerPayload) {
  const plaintext = Buffer.from(JSON.stringify(innerPayload))
  const encrypted = await e2eEncrypt(plaintext, serverPk)
  const payloadB64 = toBase64(encrypted)
  return JSON.stringify({ payload: payloadB64 })
}

async function post(path, body) {
  const res = await fetch(`http://127.0.0.1:${SERVER_PORT}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  })
  const text = await res.text()
  let json
  try { json = JSON.parse(text) } catch { json = null }
  return { status: res.status, text, json }
}

async function get(path) {
  const res = await fetch(`http://127.0.0.1:${SERVER_PORT}${path}`)
  return { status: res.status, json: await res.json() }
}

// ── Test runner ───────────────────────────────────────────────────────────

let rustProcess
let passed = 0
let failed = 0
const failures = []

async function test(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  ✅ ${name}`)
  } catch (e) {
    failed++
    failures.push({ name, error: e.message })
    console.log(`  ❌ ${name}: ${e.message}`)
  }
}

async function main() {
  // Clean up
  if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true })
  mkdirSync(DATA_DIR, { recursive: true })

  // ── Set up a local service for testing CLI bridge ──────────────────────
  const localSvcDir = join(DATA_DIR, 'services', 'testlocal')
  mkdirSync(localSvcDir, { recursive: true })

  // service.toml: local type with mock commands
  const echoScript = join(localSvcDir, 'echo.sh')
  const signScript = join(localSvcDir, 'sign.sh')
  const envScript = join(localSvcDir, 'env-key.sh')
  writeFileSync(join(localSvcDir, 'service.toml'), `
[service]
id = "testlocal"
name = "Test Local"
sub = "Local bridge test"
category = "integration"

[upstream]
type = "local"

[[upstream.apis]]
method = "GET"
path = "/echo"
command = "${echoScript}"

[[upstream.apis]]
method = "POST"
path = "/sign"
command = "${signScript}"

[[upstream.apis]]
method = "GET"
path = "/env-key"
env = { INJECTED_SECRET = "{{auth.secret}}" }
command = "${envScript}"

[policy.levels]
read = "allow"
write = "allow"
`)

  // GET /echo: returns static JSON
  writeFileSync(echoScript, `#!/bin/sh
echo '{"address":"0xDEAD","ok":true}'
`)
  chmodSync(echoScript, '755')

  // POST /sign: reads stdin body and wraps it
  writeFileSync(signScript, `#!/bin/sh
BODY=$(cat)
echo "{\\"signed\\":true,\\"input\\":$BODY}"
`)
  chmodSync(signScript, '755')

  // GET /env-key: echoes the injected env var (resolves {{auth.secret}} from vault)
  writeFileSync(envScript, `#!/bin/sh
echo "{\\"secret\\":\\"$INJECTED_SECRET\\"}"
`)
  chmodSync(envScript, '755')

  // Start Rust server
  console.log('Starting Rust server...')
  rustProcess = spawn(RUST_BIN, ['--rate-limit', '0'], {
    env: {
      ...process.env,
      SAFECLAW_DATA: DATA_DIR,
      SAFECLAW_PORT: String(SERVER_PORT),
      SAFECLAW_PROXY_PORT: String(PROXY_PORT),
      SAFECLAW_ORIGIN: ORIGIN,
      SAFECLAW_RP_ID: RP_ID,
      SAFECLAW_PROXY_BIND: '127.0.0.1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  // Capture all server output for debugging
  let serverOutput = ''
  rustProcess.stdout.on('data', (d) => { serverOutput += d.toString() })
  rustProcess.stderr.on('data', (d) => { serverOutput += d.toString() })
  rustProcess.on('exit', (code) => {
    if (code !== null && code !== 0) {
      console.error(`\n⚠️  Server exited with code ${code}. Last output:\n${serverOutput.slice(-500)}`)
    }
  })

  // Wait for server to start
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Server start timeout. Output: ' + serverOutput)), 5000)
    const check = () => {
      if (serverOutput.includes('Server listening') || serverOutput.includes('server listening') || serverOutput.includes('listening on')) {
        clearTimeout(timeout)
        resolve()
      } else {
        setTimeout(check, 100)
      }
    }
    check()
  })

  console.log('Rust server running. Starting cross-tests...\n')

  // ── Tests ───────────────────────────────────────────────────────────────

  let serverPk

  await test('GET /health returns correct fields', async () => {
    const { status, json } = await get('/health')
    assert.equal(status, 200)
    assert.equal(json.status, 'ok')
    assert.equal(json.locked, true)
    assert.equal(typeof json.uptime, 'number')
    assert.equal(json.version, '0.3.0')
  })

  await test('GET /pk returns JWK public key', async () => {
    const { status, json } = await get('/pk')
    assert.equal(status, 200)
    assert.ok(json.pk)
    assert.equal(json.pk.kty, 'EC')
    assert.equal(json.pk.crv, 'P-256')
    assert.ok(json.pk.x)
    assert.ok(json.pk.y)
    assert.equal(json.pk.d, undefined) // no private key leaked
    serverPk = json.pk
  })

  await test('E2E encrypt (JS) → decrypt (Rust) via /setup', async () => {
    const passkey = await createFakePasskey()
    const userKey = await deriveUserKey()
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const secrets = {
      services: {
        openai: {
          upstream: 'https://api.openai.com',
          auth: { type: 'header', name: 'authorization', prefix: 'Bearer', value: 'sk-test-key' },
        },
        testlocal: {
          // No upstream — local service (CLI bridge)
          auth: { type: 'key', secret: '0xdeadbeef' },
          category: 'integration',
          levels: { read: 'allow', write: 'allow' },
        },
      }
    }

    // config: non-secret data, should be forwarded to webhook (never stored in vault)
    const config = {
      channels: { telegram: { token: 'bot123:fake', ownerId: '12345' } },
      defaultModel: 'anthropic/claude-sonnet-4-20250514',
    }

    const innerPayload = {
      passkeys: [{ credentialId: passkey.credentialId, x: passkey.x, y: passkey.y, deviceName: 'CrossTest' }],
      secrets,
      config,
      userKeys: [toBase64(userKey)],
      nonce,
      assertions: [assertion],
    }

    const body = await makeAuthPayload(serverPk, innerPayload)
    let res
    try {
      res = await post('/admin/setup', body)
    } catch (e) {
      // Print server output for debugging
      console.log('  Server output:', serverOutput.slice(-500))
      throw new Error(`fetch failed: ${e.message}`)
    }
    const { status, json } = res
    assert.equal(status, 200, `Setup failed (${status}): ${JSON.stringify(json)}`)
    assert.equal(json.ok, true)

    // Store for later tests
    globalThis._crossTestPasskey = passkey
    globalThis._crossTestUserKey = userKey
  })

  await test('GET /health shows unlocked after setup', async () => {
    const { json } = await get('/health')
    assert.equal(json.locked, false)
  })

  await test('Vault unlock (JS crypto → Rust server)', async () => {
    // First lock it
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce1 = toBase64(crypto.randomBytes(32))
    const assertion1 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const lockBody = await makeAuthPayload(serverPk, {
      nonce: nonce1, credentialId: passkey.credentialId, assertion: assertion1,
    })
    const lockRes = await post('/vault/lock', lockBody)
    assert.equal(lockRes.status, 200)

    // Verify locked
    const { json: health1 } = await get('/health')
    assert.equal(health1.locked, true)

    // Now unlock
    const nonce2 = toBase64(crypto.randomBytes(32))
    const assertion2 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const unlockBody = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey),
      nonce: nonce2,
      credentialId: passkey.credentialId,
      assertion: assertion2,
    })
    const unlockRes = await post('/admin/unlock', unlockBody)
    assert.equal(unlockRes.status, 200, `Unlock failed: ${JSON.stringify(unlockRes.json)}`)
    assert.equal(unlockRes.json.ok, true)

    // Verify unlocked
    const { json: health2 } = await get('/health')
    assert.equal(health2.locked, false)
  })

  await test('Vault credentials (response E2E decryption)', async () => {
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const body = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey),
      nonce,
      credentialId: passkey.credentialId,
      assertion,
    })
    const { status, json } = await post('/vault/credentials', body)
    assert.equal(status, 200, `Credentials failed: ${JSON.stringify(json)}`)
    assert.ok(json.sealed, 'Missing sealed field')

    // Decrypt the response using JS crypto (matching safeclaw-client.js deriveResponseKey + aesDecrypt)
    const nonceBuf = Buffer.from(nonce, 'base64')
    const keyMaterial = await crypto.subtle.importKey('raw', userKey, 'HKDF', false, ['deriveBits'])
    const responseKeyBits = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(nonceBuf),
      info: new TextEncoder().encode('safeclaw-response-v1'),
    }, keyMaterial, 256)

    const sealed = Buffer.from(json.sealed, 'base64')
    const iv = sealed.subarray(0, 12)
    const ct = sealed.subarray(12)
    const aesKey = await crypto.subtle.importKey(
      'raw', responseKeyBits, { name: 'AES-GCM' }, false, ['decrypt']
    )
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct)
    const secrets = JSON.parse(Buffer.from(plaintext).toString())

    assert.ok(secrets.services.openai)
    assert.equal(secrets.services.openai.auth.value, 'sk-test-key')
  })

  await test('Nonce replay rejected', async () => {
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion1 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const body1 = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce,
      credentialId: passkey.credentialId, assertion: assertion1,
    })
    const res1 = await post('/vault/credentials', body1)
    assert.equal(res1.status, 200)

    // Same nonce, new assertion — should fail
    const assertion2 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
    const body2 = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce,
      credentialId: passkey.credentialId, assertion: assertion2,
    })
    const res2 = await post('/vault/credentials', body2)
    assert.equal(res2.status, 400)
    assert.ok(res2.json.error.includes('Nonce'))
  })

  await test('Wrong origin rejected', async () => {
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce = toBase64(crypto.randomBytes(32))
    // Sign with wrong origin
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, 'https://evil.com', RP_ID)

    const body = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce,
      credentialId: passkey.credentialId, assertion,
    })
    const res = await post('/admin/unlock', body)
    assert.notEqual(res.status, 200)
  })

  await test('Wrong rpId rejected', async () => {
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, 'evil.com')

    const body = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce,
      credentialId: passkey.credentialId, assertion,
    })
    const res = await post('/admin/unlock', body)
    assert.notEqual(res.status, 200)
  })

  await test('Proxy returns locked response (OpenAI format)', async () => {
    // Lock first
    const passkey = globalThis._crossTestPasskey
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
    const lockBody = await makeAuthPayload(serverPk, {
      nonce, credentialId: passkey.credentialId, assertion,
    })
    await post('/vault/lock', lockBody)

    // Hit proxy
    const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/openai/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] }),
    })
    assert.equal(res.status, 200)
    const body = await res.json()
    assert.ok(body.choices[0].message.content.includes('locked'))
    assert.equal(body.safeclaw_locked, true)
  })

  await test('Add passkey (identity endpoint)', async () => {
    // Unlock first
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce1 = toBase64(crypto.randomBytes(32))
    const assertion1 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
    await post('/admin/unlock', await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce: nonce1,
      credentialId: passkey.credentialId, assertion: assertion1,
    }))

    // Add a second passkey
    const passkey2 = await createFakePasskey()
    const userKey2 = await deriveUserKey()
    const nonce2 = toBase64(crypto.randomBytes(32))
    const assertion2 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const body = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey),
      nonce: nonce2,
      credentialId: passkey.credentialId,
      assertion: assertion2,
      newPasskey: { credentialId: passkey2.credentialId, x: passkey2.x, y: passkey2.y, deviceName: 'CrossTest2' },
      newUserKey: toBase64(userKey2),
    })
    const res = await post('/passkeys/add', body)
    assert.equal(res.status, 200, `Add passkey failed: ${JSON.stringify(res.json)}`)

    // Verify we can unlock with the new passkey
    const nonce3 = toBase64(crypto.randomBytes(32))
    const assertion3 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
    await post('/vault/lock', await makeAuthPayload(serverPk, {
      nonce: nonce3, credentialId: passkey.credentialId, assertion: assertion3,
    }))

    const nonce4 = toBase64(crypto.randomBytes(32))
    const assertion4 = await createFakeAssertion(passkey2.keyPair.privateKey, ORIGIN, RP_ID)
    const unlockRes = await post('/admin/unlock', await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey2), nonce: nonce4,
      credentialId: passkey2.credentialId, assertion: assertion4,
    }))
    assert.equal(unlockRes.status, 200, `Unlock with new passkey failed: ${JSON.stringify(unlockRes.json)}`)
  })

  // ── NodPay integration: webauthn, passkey export, local service ──────

  await test('GET /.well-known/webauthn returns origins', async () => {
    const { status, json } = await get('/.well-known/webauthn')
    assert.equal(status, 200)
    assert.ok(Array.isArray(json.origins))
    assert.ok(json.origins.includes('https://nodpay.ai'))
  })

  await test('GET /passkeys/public returns hex coordinates', async () => {
    const { status, json } = await get('/passkeys/public')
    assert.equal(status, 200)
    assert.ok(Array.isArray(json.passkeys))
    assert.ok(json.passkeys.length >= 1, 'Expected at least 1 passkey')
    // Find any passkey with valid coordinates (order is non-deterministic)
    const pk = json.passkeys.find(p => p.deviceName === 'CrossTest') || json.passkeys[0]
    assert.ok(pk.x.startsWith('0x'), 'x should be 0x-prefixed hex')
    assert.ok(pk.y.startsWith('0x'), 'y should be 0x-prefixed hex')
    assert.equal(pk.x.length, 66, 'x should be 32 bytes = 64 hex chars + 0x prefix')
    assert.equal(pk.y.length, 66, 'y should be 32 bytes = 64 hex chars + 0x prefix')
    assert.ok(pk.credentialId)
  })

  await test('Local service: GET /echo via proxy', async () => {
    // Ensure vault is unlocked
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey

    // Check health first to see if unlocked
    const { json: health } = await get('/health')
    if (health.locked) {
      const nonce = toBase64(crypto.randomBytes(32))
      const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
      await post('/admin/unlock', await makeAuthPayload(serverPk, {
        userKey: toBase64(userKey), nonce,
        credentialId: passkey.credentialId, assertion,
      }))
    }

    const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/testlocal/echo`, {
      method: 'GET',
    })
    assert.equal(res.status, 200, `Local GET failed: ${res.status}`)
    const body = await res.json()
    assert.equal(body.ok, true)
    assert.equal(body.address, '0xDEAD')
  })

  await test('Local service: POST /sign via proxy', async () => {
    const payload = { data: '0x1234', to: '0xABCD' }
    const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/testlocal/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    assert.equal(res.status, 200, `Local POST failed: ${res.status}`)
    const body = await res.json()
    assert.equal(body.signed, true)
    assert.deepStrictEqual(body.input, payload)
  })

  await test('Local service: unknown path returns 404', async () => {
    const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/testlocal/unknown`, {
      method: 'GET',
    })
    assert.equal(res.status, 404)
  })

  await test('Local service: env injection resolves {{auth.secret}}', async () => {
    const res = await fetch(`http://127.0.0.1:${PROXY_PORT}/testlocal/env-key`)
    assert.equal(res.status, 200, `Env inject GET failed: ${res.status}`)
    const body = await res.json()
    assert.equal(body.secret, '0xdeadbeef', `Expected vault secret, got: ${body.secret}`)
  })

  // ── Vault update (destructive — runs last as it replaces all secrets) ──

  await test('Update vault secrets', async () => {
    const passkey = globalThis._crossTestPasskey
    const userKey = globalThis._crossTestUserKey
    const nonce = toBase64(crypto.randomBytes(32))
    const assertion = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)

    const body = await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce,
      credentialId: passkey.credentialId, assertion,
      newSecrets: { services: { anthropic: { upstream: 'https://api.anthropic.com', auth: { type: 'header', name: 'x-api-key', value: 'sk-ant-test' } } } },
    })
    const res = await post('/vault/update', body)
    assert.equal(res.status, 200, `Update failed: ${JSON.stringify(res.json)}`)

    // Verify updated secrets
    const nonce2 = toBase64(crypto.randomBytes(32))
    const assertion2 = await createFakeAssertion(passkey.keyPair.privateKey, ORIGIN, RP_ID)
    const credRes = await post('/vault/credentials', await makeAuthPayload(serverPk, {
      userKey: toBase64(userKey), nonce: nonce2,
      credentialId: passkey.credentialId, assertion: assertion2,
    }))
    assert.equal(credRes.status, 200)

    // Decrypt and verify
    const nonceBuf = Buffer.from(nonce2, 'base64')
    const keyMaterial = await crypto.subtle.importKey('raw', userKey, 'HKDF', false, ['deriveBits'])
    const responseKeyBits = await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256',
      salt: new Uint8Array(nonceBuf),
      info: new TextEncoder().encode('safeclaw-response-v1'),
    }, keyMaterial, 256)
    const sealed = Buffer.from(credRes.json.sealed, 'base64')
    const aesKey = await crypto.subtle.importKey('raw', responseKeyBits, { name: 'AES-GCM' }, false, ['decrypt'])
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.subarray(0, 12) }, aesKey, sealed.subarray(12))
    const secrets = JSON.parse(Buffer.from(plaintext).toString())
    assert.ok(secrets.services.anthropic)
    assert.equal(secrets.services.anthropic.auth.value, 'sk-ant-test')
  })

  // ── Summary ─────────────────────────────────────────────────────────────

  console.log(`\n${'═'.repeat(50)}`)
  console.log(`Cross-test results: ${passed} passed, ${failed} failed`)
  if (failures.length > 0) {
    console.log('\nFailures:')
    for (const f of failures) console.log(`  ❌ ${f.name}: ${f.error}`)
  }
  console.log(`${'═'.repeat(50)}`)

  process.exit(failed > 0 ? 1 : 0)
}

main()
  .catch(err => { console.error('Fatal:', err); process.exit(1) })
  .finally(() => { if (rustProcess) rustProcess.kill() })
