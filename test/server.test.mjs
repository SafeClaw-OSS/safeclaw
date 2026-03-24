import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { generateDEK, e2eEncrypt, deriveResponseKey, decrypt } from '../lib/crypto.mjs'
import { createServer } from '../lib/server.mjs'
import {
  SAMPLE_SECRETS,
  makeP256Credential, makeAssertion, httpRequest,
  createMockProxy, getFreePort, makeNonce,
} from './helpers.mjs'

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

  const assertion = await makeAssertion(cred.privateKey)
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'TestPhone' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [assertion],
  }
  const encrypted = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/setup', {
    payload: encrypted.toString('base64'),
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.ok(existsSync(join(dir, 'vault.enc')))
  assert.ok(existsSync(join(dir, 'passkeys.json')))
  assert.ok(existsSync(join(dir, `wrapped_dek_${credentialId}.bin`)))
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

  const setupAssertion = await makeAssertion(cred.privateKey)
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'Laptop' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertion],
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
  })

  proxy.lock()
  assert.strictEqual(proxy.isLocked(), true)

  const unlockAssertion = await makeAssertion(cred.privateKey)
  const unlockPayload = { userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: unlockAssertion }
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify(unlockPayload)), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.isLocked(), false)
})

// ── POST /admin/status ────────────────────────────────────────────────────────

test('POST /admin/status returns status without auth when no vault exists', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { status, body } = await httpRequest(port, 'POST', '/admin/status', {})
  assert.strictEqual(status, 200)
  assert.strictEqual(body.locked, true)
  assert.deepStrictEqual(body.passkeys, [])
  assert.ok(typeof body.uptime === 'number')
})

test('POST /admin/status requires passkey auth after setup', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sc-srv-test-'))
  const proxy = createMockProxy()
  const port = await getFreePort()
  const server = await createServer({ port, dataDir: dir, proxy })
  t.after(() => { server.close(); rmSync(dir, { recursive: true }) })

  const { body: { vmPk } } = await httpRequest(port, 'GET', '/vmPk')
  const credentialId = 'cred-status-001'
  const userKey = generateDEK()
  const cred = await makeP256Credential()
  const setupAssertion2 = await makeAssertion(cred.privateKey)
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertion2],
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
  })

  const statusAssertion = await makeAssertion(cred.privateKey)
  const statusPayload = { nonce: makeNonce(), credentialId, assertion: statusAssertion }
  const statusEnc = await e2eEncrypt(Buffer.from(JSON.stringify(statusPayload)), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/status', {
    payload: statusEnc.toString('base64'),
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.locked, false)
  assert.deepStrictEqual(body.passkeys, [credentialId])
  assert.deepStrictEqual(body.services, ['anthropic'])
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

  const assertion1 = await makeAssertion(cred1.privateKey)
  const setupPayload1 = {
    passkeys: [{ credentialId: 'cred-replay-001', x: cred1.x, y: cred1.y, deviceName: 'Dev' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce,
    assertions: [assertion1],
  }
  const enc1 = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload1)), vmPk)
  const first = await httpRequest(port, 'POST', '/setup', {
    payload: enc1.toString('base64'),
  })
  assert.strictEqual(first.status, 200)

  // Second setup with same nonce — vault exists, provide existing auth
  const assertion2 = await makeAssertion(cred2.privateKey)
  const existingAssertion = await makeAssertion(cred1.privateKey)
  const setupPayload2 = {
    passkeys: [{ credentialId: 'cred-replay-002', x: cred2.x, y: cred2.y, deviceName: 'Dev2' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce,
    assertions: [assertion2],
    existingCredentialId: 'cred-replay-001',
    existingAssertion,
  }
  const enc2 = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload2)), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/setup', {
    payload: enc2.toString('base64'),
  })
  assert.strictEqual(status, 400)
  assert.ok(body.error)
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

  const setupAssertion3 = await makeAssertion(cred.privateKey)
  const setupPayload = {
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'Dev' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertion3],
  }
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify(setupPayload)), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
  })
  proxy.lock()

  const nonce = makeNonce()
  const unlockAssertion1 = await makeAssertion(cred.privateKey)
  const unlockEnc1 = await e2eEncrypt(Buffer.from(JSON.stringify({ userKey: userKey.toString('base64'), nonce, credentialId, assertion: unlockAssertion1 })), vmPk)
  const first = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc1.toString('base64'),
  })
  assert.strictEqual(first.status, 200)

  proxy.lock()

  const unlockAssertion2 = await makeAssertion(cred.privateKey)
  const unlockEnc2 = await e2eEncrypt(Buffer.from(JSON.stringify({ userKey: userKey.toString('base64'), nonce, credentialId, assertion: unlockAssertion2 })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc2.toString('base64'),
  })
  assert.strictEqual(status, 400)
  assert.ok(body.error)
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

  const setupAssertionA = await makeAssertion(cred.privateKey)
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertionA],
  })), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
  })

  const nonce = crypto.randomBytes(32)
  const viewAssertion = await makeAssertion(cred.privateKey)
  const viewEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'),
    nonce: nonce.toString('base64'),
    credentialId,
    assertion: viewAssertion,
  })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: viewEnc.toString('base64'),
  })

  assert.strictEqual(status, 200)
  assert.ok(typeof body.sealed === 'string')

  const responseKey = await deriveResponseKey(userKey, nonce)
  const secrets = JSON.parse((await decrypt(responseKey, Buffer.from(body.sealed, 'base64'))).toString())
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

  const setupAssertionB = await makeAssertion(cred.privateKey)
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertionB],
  })), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
  })

  const nonce = crypto.randomBytes(32)
  const viewAssertion1 = await makeAssertion(cred.privateKey)
  const viewPayload = { userKey: userKey.toString('base64'), nonce: nonce.toString('base64'), credentialId, assertion: viewAssertion1 }

  const enc1 = await e2eEncrypt(Buffer.from(JSON.stringify(viewPayload)), vmPk)
  const first = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: enc1.toString('base64'),
  })
  assert.strictEqual(first.status, 200)

  const viewAssertion2 = await makeAssertion(cred.privateKey)
  const viewPayload2 = { userKey: userKey.toString('base64'), nonce: nonce.toString('base64'), credentialId, assertion: viewAssertion2 }
  const enc2 = await e2eEncrypt(Buffer.from(JSON.stringify(viewPayload2)), vmPk)
  const { status } = await httpRequest(port, 'POST', '/admin/credentials', {
    payload: enc2.toString('base64'),
  })
  assert.strictEqual(status, 400)
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

  const setupAssertionC = await makeAssertion(cred.privateKey)
  const setupEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    passkeys: [{ credentialId, x: cred.x, y: cred.y, deviceName: 'PC' }],
    secrets: SAMPLE_SECRETS,
    userKeys: [userKey.toString('base64')],
    nonce: makeNonce(),
    assertions: [setupAssertionC],
  })), vmPk)
  await httpRequest(port, 'POST', '/setup', {
    payload: setupEnc.toString('base64'),
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

  const updateAssertion = await makeAssertion(cred.privateKey)
  const updateEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'),
    nonce: makeNonce(),
    credentialId,
    newSecrets,
    assertion: updateAssertion,
  })), vmPk)
  const { status, body } = await httpRequest(port, 'POST', '/admin/update-secrets', {
    payload: updateEnc.toString('base64'),
  })

  assert.strictEqual(status, 200)
  assert.strictEqual(body.ok, true)
  assert.strictEqual(proxy.getSecrets().services.anthropic.auth.value, 'sk-ant-updated')

  // Verify via unlock
  proxy.lock()
  const unlockAssertionC = await makeAssertion(cred.privateKey)
  const unlockEnc = await e2eEncrypt(Buffer.from(JSON.stringify({
    userKey: userKey.toString('base64'), nonce: makeNonce(), credentialId, assertion: unlockAssertionC,
  })), vmPk)
  const unlockRes = await httpRequest(port, 'POST', '/unlock', {
    payload: unlockEnc.toString('base64'),
  })
  assert.strictEqual(unlockRes.status, 200)
  assert.strictEqual(proxy.getSecrets().services.anthropic.auth.value, 'sk-ant-updated')
})
