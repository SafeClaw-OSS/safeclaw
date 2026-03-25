import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { generateDEK, e2eEncrypt } from '../lib/crypto.mjs'
import { createServer } from '../lib/server.mjs'
import {
  SAMPLE_SECRETS,
  makeP256Credential, makeAssertion, httpRequest,
  createMockProxy, getFreePort, makeNonce,
} from './helpers.mjs'

// Helper: full setup, returns { credentialId, userKey, cred, vmPk }
async function doSetup(port) {
  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')
  const credentialId = 'cred-' + crypto.randomBytes(4).toString('hex')
  const userKey = generateDEK()
  const cred = await makeP256Credential()

  const setupAssertion = await makeAssertion(cred.privateKey)
  const enc = await e2eEncrypt(Buffer.from(JSON.stringify({
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'TestDevice' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertion],
  })), vmPk)
  const res = await httpRequest(port, 'POST', '/setup', {
    payload: enc.toString('base64'),
  })
  assert.strictEqual(res.status, 200)
  return { credentialId, userKey, cred, vmPk }
}

// ══════════════════════════════════════════════════════════════════════════════
// Rate Limit
// ══════════════════════════════════════════════════════════════════════════════

test('Rate limit: rejects excessive POST requests from same IP', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, rateLimit: 3, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  // First 3 requests should not be rate limited
  for (let i = 0; i < 3; i++) {
    const { status } = await httpRequest(port, 'POST', '/admin/status', {})
    assert.notStrictEqual(status, 429, `request ${i + 1} should not be rate limited`)
  }
  // 4th request should be rate limited
  const { status, body } = await httpRequest(port, 'POST', '/admin/status', {})
  assert.strictEqual(status, 429)
  assert.ok(body.error.includes('Rate limit'))
})

test('Rate limit: disabled when rateLimit=0', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, rateLimit: 0, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  // Should never get 429
  for (let i = 0; i < 5; i++) {
    const { status } = await httpRequest(port, 'POST', '/admin/status', {})
    assert.notStrictEqual(status, 429)
  }
})

// ══════════════════════════════════════════════════════════════════════════════
// 🔴-2: Admin Endpoint Auth
// ══════════════════════════════════════════════════════════════════════════════

test('🔴-2: /admin/lock requires passkey assertion', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk } = await doSetup(port)

  // Without auth — should fail
  const { status: s1 } = await httpRequest(port, 'POST', '/admin/lock', { noauth: true })
  assert.ok(s1 >= 400)

  // With auth — should succeed
  const lockAssertion = await makeAssertion(cred.privateKey)
  const lockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({ nonce: makeNonce(), credentialId, assertion: lockAssertion })), vmPk)
  const { status: s2, body } = await httpRequest(port, 'POST', '/admin/lock', {
    payload: lockEnc.toString('base64'),
  })
  assert.strictEqual(s2, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.isLocked(), true)
})

test('🔴-2: /admin/status rejects unauthenticated request after setup', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  await doSetup(port)

  const { status } = await httpRequest(port, 'POST', '/admin/status', { noauth: true })
  assert.ok(status >= 400)
})

// ══════════════════════════════════════════════════════════════════════════════
// 🔴-3: Assertion null x/y bypass
// ══════════════════════════════════════════════════════════════════════════════

test('🔴-3: null x/y passkey is rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')
  const nullAssertion = {
    authenticatorData: crypto.randomBytes(37).toString('base64'),
    clientDataJSON: Buffer.from('{}').toString('base64'),
    signature: crypto.randomBytes(64).toString('base64'),
  }
  const enc = await e2eEncrypt(Buffer.from(JSON.stringify({
    passkeys: [{ credentialId: 'cred-nullxy', x: null, y: null, deviceName: 'Null' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [generateDEK().toString('base64')],
    nonce: makeNonce(),
    assertions: [nullAssertion],
  })), vmPk)

  const { status } = await httpRequest(port, 'POST', '/setup', {
    payload: enc.toString('base64'),
  })
  assert.strictEqual(status, 401)
})

// ══════════════════════════════════════════════════════════════════════════════
// 🔴-4: WebAuthn assertion validation
// ══════════════════════════════════════════════════════════════════════════════

test('🔴-4: wrong origin rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk, userKey } = await doSetup(port)
  proxy.lock()

  const evilOriginAssertion = await makeAssertion(cred.privateKey, { origin: 'https://evil.com' })
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: evilOriginAssertion,
  })), vmPk)
  const { status } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })
  assert.strictEqual(status, 401)
})

test('🔴-4: wrong rpId rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk, userKey } = await doSetup(port)
  proxy.lock()

  const evilRpIdAssertion = await makeAssertion(cred.privateKey, { rpId: 'evil.com' })
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: evilRpIdAssertion,
  })), vmPk)
  const { status } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })
  assert.strictEqual(status, 401)
})

test('🔴-4: wrong type (webauthn.create) rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk, userKey } = await doSetup(port)
  proxy.lock()

  const wrongTypeAssertion = await makeAssertion(cred.privateKey, { type: 'webauthn.create' })
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: wrongTypeAssertion,
  })), vmPk)
  const { status } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })
  assert.strictEqual(status, 401)
})

test('🔴-4: missing UP flag rejected', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk, userKey } = await doSetup(port)
  proxy.lock()

  const noUpFlagAssertion = await makeAssertion(cred.privateKey, { upFlag: false })
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: noUpFlagAssertion,
  })), vmPk)
  const { status } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })
  assert.strictEqual(status, 401)
})

// ══════════════════════════════════════════════════════════════════════════════
// 🔵-3: Setup overwrite protection
// ══════════════════════════════════════════════════════════════════════════════

test('🔵-3: setup with existing vault requires existing passkey auth', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk } = await doSetup(port)

  const newCred = await makeP256Credential()
  const overwritePayload = {
    passkeys: [{ credentialId: 'cred-overwrite', x: newCred.x, y: newCred.y, deviceName: 'Evil' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [generateDEK().toString('base64')],
    nonce: makeNonce(),
  }

  // Without existing auth — rejected
  const overwriteAssertion1 = await makeAssertion(newCred.privateKey)
  const enc1 = await e2eEncrypt(Buffer.from(JSON.stringify({ ...overwritePayload, assertions: [overwriteAssertion1] })), vmPk)
  const { status: s1 } = await httpRequest(port, 'POST', '/setup', {
    payload: enc1.toString('base64'),
  })
  assert.strictEqual(s1, 401)

  // With existing auth — succeeds (fresh nonce since first attempt consumed the old one)
  const overwriteAssertion2 = await makeAssertion(newCred.privateKey)
  const existingAuth = await makeAssertion(cred.privateKey)
  const enc2 = await e2eEncrypt(Buffer.from(JSON.stringify({
    ...overwritePayload,
    nonce: makeNonce(),
    assertions: [overwriteAssertion2],
    existingCredentialId: credentialId,
    existingAssertion: existingAuth,
  })), vmPk)
  const { status: s2 } = await httpRequest(port, 'POST', '/setup', {
    payload: enc2.toString('base64'),
  })
  assert.strictEqual(s2, 200)
})

// ══════════════════════════════════════════════════════════════════════════════
// 🟡-1: Passkey CRUD
// ══════════════════════════════════════════════════════════════════════════════

test('🟡-1: add-passkey adds a new credential', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, userKey, cred, vmPk } = await doSetup(port)

  const newCred = await makeP256Credential()
  const addAssertion = await makeAssertion(cred.privateKey)
  const addEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    credentialId,
    userKey: userKey.toString('base64'),
    nonce: makeNonce(),
    newPasskey: { credentialId: 'new-cred-001', x: newCred.x, y: newCred.y, deviceName: 'NewPhone' },
    newUserKey: generateDEK().toString('base64'),
    assertion: addAssertion,
  })), vmPk)

  const { status, body } = await httpRequest(port, 'POST', '/admin/add-passkey', {
    payload: addEnc.toString('base64'),
  })
  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.ok(existsSync(join(dir, 'wrapped_dek_new-cred-001.bin')))
})

test('🟡-1: remove-passkey removes a credential', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, userKey, cred, vmPk } = await doSetup(port)

  // Add second passkey first
  const newCred = await makeP256Credential()
  const addAssertion2 = await makeAssertion(cred.privateKey)
  const addEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    credentialId,
    userKey: userKey.toString('base64'),
    nonce: makeNonce(),
    newPasskey: { credentialId: 'removable', x: newCred.x, y: newCred.y, deviceName: 'Temp' },
    newUserKey: generateDEK().toString('base64'),
    assertion: addAssertion2,
  })), vmPk)
  await httpRequest(port, 'POST', '/admin/add-passkey', {
    payload: addEnc.toString('base64'),
  })

  // Remove it
  const removeAssertion = await makeAssertion(cred.privateKey)
  const removeEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    credentialId,
    nonce: makeNonce(),
    removeCredentialId: 'removable',
    assertion: removeAssertion,
  })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/remove-passkey', {
    payload: removeEnc.toString('base64'),
  })
  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.ok(!existsSync(join(dir, 'wrapped_dek_removable.bin')))
})

test('🟡-1: cannot remove the last passkey', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy, expectedOrigin: "http://localhost", rpId: "localhost" })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk } = await doSetup(port)

  const removeLastAssertion = await makeAssertion(cred.privateKey)
  const removeEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    credentialId,
    nonce: makeNonce(),
    removeCredentialId: credentialId,
    assertion: removeLastAssertion,
  })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/remove-passkey', {
    payload: removeEnc.toString('base64'),
  })
  assert.strictEqual(status, 400)
  assert.ok(body.error.includes('last passkey'))
})

// ══════════════════════════════════════════════════════════════════════════════
// 🟡-2: Admin VM Ops
// ══════════════════════════════════════════════════════════════════════════════

test('🟡-2: /admin/restart locks proxy and exits with 0', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  let exitCode = null
  const server = await createServer({
    port, dataDir: dir, proxy,
    expectedOrigin: 'http://localhost', rpId: 'localhost',
    exitFn: (code) => { exitCode = code },
  })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk } = await doSetup(port)

  const restartAssertion = await makeAssertion(cred.privateKey)
  const enc = await e2eEncrypt(Buffer.from(JSON.stringify({ nonce: makeNonce(), credentialId, assertion: restartAssertion })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/restart', {
    payload: enc.toString('base64'),
  })
  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.isLocked(), true)
  assert.strictEqual(exitCode, 0)
})

test('🟡-2: /admin/shutdown locks proxy and exits with 1', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-sec-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  let exitCode = null
  const server = await createServer({
    port, dataDir: dir, proxy,
    expectedOrigin: 'http://localhost', rpId: 'localhost',
    exitFn: (code) => { exitCode = code },
  })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { credentialId, cred, vmPk } = await doSetup(port)

  const shutdownAssertion = await makeAssertion(cred.privateKey)
  const enc = await e2eEncrypt(Buffer.from(JSON.stringify({ nonce: makeNonce(), credentialId, assertion: shutdownAssertion })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/shutdown', {
    payload: enc.toString('base64'),
  })
  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.isLocked(), true)
  assert.strictEqual(exitCode, 1)
})

// Admin unauth rejection pattern: covered by 🔴-2 /admin/lock test (same pattern)
