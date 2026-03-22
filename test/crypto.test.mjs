import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  generateVmKeypair,
  loadOrCreateVmKeypair,
  deriveKEK,
  encrypt,
  decrypt,
  generateDEK,
  wrapDEK,
  unwrapDEK,
  e2eEncrypt,
  e2eDecrypt,
  zeroize,
} from '../lib/crypto.mjs'

// ── generateVmKeypair ─────────────────────────────────────────────────────────

test('generateVmKeypair returns pk/sk as JWK objects with P-256 curve', async () => {
  const { pk, sk } = await generateVmKeypair()
  assert.strictEqual(pk.kty, 'EC')
  assert.strictEqual(pk.crv, 'P-256')
  assert.ok(pk.x, 'pk should have x coordinate')
  assert.ok(pk.y, 'pk should have y coordinate')
  assert.strictEqual(pk.d, undefined, 'pk should not contain private key')
  assert.strictEqual(sk.kty, 'EC')
  assert.strictEqual(sk.crv, 'P-256')
  assert.ok(sk.d, 'sk should contain private key d')
})

test('generateVmKeypair produces unique keypairs', async () => {
  const kp1 = await generateVmKeypair()
  const kp2 = await generateVmKeypair()
  assert.notDeepStrictEqual(kp1.pk, kp2.pk)
  assert.notDeepStrictEqual(kp1.sk, kp2.sk)
})

// ── loadOrCreateVmKeypair ─────────────────────────────────────────────────────

test('loadOrCreateVmKeypair creates keypair on first call', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'safeclaw-test-'))
  try {
    const { pk, sk } = await loadOrCreateVmKeypair(dir)
    assert.strictEqual(pk.kty, 'EC')
    assert.strictEqual(sk.crv, 'P-256')
    assert.ok(sk.d)
  } finally {
    rmSync(dir, { recursive: true })
  }
})

test('loadOrCreateVmKeypair loads same keypair on subsequent calls', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'safeclaw-test-'))
  try {
    const kp1 = await loadOrCreateVmKeypair(dir)
    const kp2 = await loadOrCreateVmKeypair(dir)
    assert.deepStrictEqual(kp1.pk, kp2.pk)
    assert.deepStrictEqual(kp1.sk, kp2.sk)
  } finally {
    rmSync(dir, { recursive: true })
  }
})

// ── deriveKEK ─────────────────────────────────────────────────────────────────

test('deriveKEK returns a 32-byte Buffer', async () => {
  const userKey = Buffer.alloc(32, 0xaa)
  const { sk: vmSk } = await generateVmKeypair()
  const kek = await deriveKEK(userKey, vmSk)
  assert.ok(Buffer.isBuffer(kek))
  assert.strictEqual(kek.length, 32)
})

test('deriveKEK is deterministic', async () => {
  const userKey = Buffer.alloc(32, 0x11)
  const { sk: vmSk } = await generateVmKeypair()
  const kek1 = await deriveKEK(userKey, vmSk)
  const kek2 = await deriveKEK(userKey, vmSk)
  assert.deepStrictEqual(kek1, kek2)
})

test('deriveKEK produces different output for different inputs', async () => {
  const { sk: vmSk } = await generateVmKeypair()
  const kek1 = await deriveKEK(Buffer.alloc(32, 0x01), vmSk)
  const kek2 = await deriveKEK(Buffer.alloc(32, 0x02), vmSk)
  assert.notDeepStrictEqual(kek1, kek2)
})

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

test('encrypt/decrypt round-trip', async () => {
  const key = crypto.randomBytes(32)
  const plaintext = Buffer.from('Hello, SafeClaw!')
  const sealed = await encrypt(key, plaintext)
  assert.ok(Buffer.isBuffer(sealed))
  const decrypted = await decrypt(key, sealed)
  assert.deepStrictEqual(decrypted, plaintext)
})

test('encrypt produces different ciphertexts for same input (random IV)', async () => {
  const key = Buffer.alloc(32, 0x42)
  const msg = Buffer.from('same plaintext')
  const ct1 = await encrypt(key, msg)
  const ct2 = await encrypt(key, msg)
  assert.notDeepStrictEqual(ct1, ct2)
})

test('decrypt throws on wrong key', async () => {
  const key = Buffer.alloc(32, 0x01)
  const wrongKey = Buffer.alloc(32, 0x02)
  const sealed = await encrypt(key, Buffer.from('secret'))
  await assert.rejects(() => decrypt(wrongKey, sealed), /Decryption failed/)
})

test('decrypt throws on tampered ciphertext', async () => {
  const key = Buffer.alloc(32, 0x55)
  const sealed = await encrypt(key, Buffer.from('tamper me'))
  sealed[sealed.length - 1] ^= 0xff  // flip a byte
  await assert.rejects(() => decrypt(key, sealed), /Decryption failed/)
})

// ── generateDEK ───────────────────────────────────────────────────────────────

test('generateDEK returns a 32-byte random Buffer', () => {
  const dek1 = generateDEK()
  const dek2 = generateDEK()
  assert.strictEqual(dek1.length, 32)
  assert.strictEqual(dek2.length, 32)
  assert.notDeepStrictEqual(dek1, dek2)
})

// ── wrapDEK / unwrapDEK ───────────────────────────────────────────────────────

test('wrapDEK/unwrapDEK round-trip', async () => {
  const dek = generateDEK()
  const kek = Buffer.alloc(32, 0x42)
  const wrapped = await wrapDEK(dek, kek)
  assert.ok(Buffer.isBuffer(wrapped))
  const unwrapped = await unwrapDEK(wrapped, kek)
  assert.deepStrictEqual(unwrapped, dek)
})

test('unwrapDEK throws with wrong KEK', async () => {
  const dek = generateDEK()
  const kek = Buffer.alloc(32, 0x01)
  const wrongKek = Buffer.alloc(32, 0x02)
  const wrapped = await wrapDEK(dek, kek)
  await assert.rejects(() => unwrapDEK(wrapped, wrongKek), /Decryption failed/)
})

// ── Envelope: multiple passkeys wrapping the same DEK ────────────────────────

test('multiple userKeys can each wrap/unwrap the same DEK independently', async () => {
  const { sk: vmSk } = await generateVmKeypair()
  const dek = generateDEK()

  const userKeys = [
    Buffer.alloc(32, 0x11),
    Buffer.alloc(32, 0x22),
    Buffer.alloc(32, 0x33),
  ]

  // Each user wraps the DEK with their own KEK
  const wrappedDEKs = []
  for (const uk of userKeys) {
    const kek = await deriveKEK(uk, vmSk)
    wrappedDEKs.push(await wrapDEK(dek, kek))
  }

  // Each user can recover the DEK
  for (let i = 0; i < userKeys.length; i++) {
    const kek = await deriveKEK(userKeys[i], vmSk)
    const recovered = await unwrapDEK(wrappedDEKs[i], kek)
    assert.deepStrictEqual(recovered, dek, `User ${i} failed to recover DEK`)
  }

  // Wrapped blobs differ (independent IVs)
  assert.notDeepStrictEqual(wrappedDEKs[0], wrappedDEKs[1])
  assert.notDeepStrictEqual(wrappedDEKs[1], wrappedDEKs[2])
})

test('wrong userKey cannot unwrap another user\'s wrapped DEK', async () => {
  const { sk: vmSk } = await generateVmKeypair()
  const dek = generateDEK()
  const uk1 = Buffer.alloc(32, 0xaa)
  const uk2 = Buffer.alloc(32, 0xbb)
  const kek1 = await deriveKEK(uk1, vmSk)
  const kek2 = await deriveKEK(uk2, vmSk)
  const wrapped1 = await wrapDEK(dek, kek1)
  await assert.rejects(() => unwrapDEK(wrapped1, kek2), /Decryption failed/)
})

// ── e2eEncrypt / e2eDecrypt ───────────────────────────────────────────────────

test('e2eEncrypt/e2eDecrypt round-trip', async () => {
  const { pk, sk } = await generateVmKeypair()
  const plaintext = Buffer.from('E2E secret message')
  const ciphertext = await e2eEncrypt(plaintext, pk)
  assert.ok(Buffer.isBuffer(ciphertext))
  const decrypted = await e2eDecrypt(ciphertext, pk, sk)
  assert.deepStrictEqual(decrypted, plaintext)
})

test('e2eEncrypt/e2eDecrypt works with empty plaintext', async () => {
  const { pk, sk } = await generateVmKeypair()
  const plaintext = Buffer.alloc(0)
  const ciphertext = await e2eEncrypt(plaintext, pk)
  const decrypted = await e2eDecrypt(ciphertext, pk, sk)
  assert.deepStrictEqual(decrypted, plaintext)
})

test('e2eDecrypt throws with wrong keypair', async () => {
  const { pk } = await generateVmKeypair()
  const { pk: wp, sk: ws } = await generateVmKeypair()
  const ciphertext = await e2eEncrypt(Buffer.from('secret'), pk)
  await assert.rejects(() => e2eDecrypt(ciphertext, wp, ws), /E2E decryption failed/)
})

// ── zeroize ───────────────────────────────────────────────────────────────────

test('zeroize fills single buffer with zeros', () => {
  const buf = Buffer.from('sensitive data')
  zeroize(buf)
  assert.ok(buf.every(b => b === 0), 'buffer should be all zeros after zeroize')
})

test('zeroize fills multiple buffers with zeros', () => {
  const buf1 = Buffer.from('key material 1')
  const buf2 = Buffer.from('key material 2')
  const buf3 = Buffer.alloc(32, 0xff)
  zeroize(buf1, buf2, buf3)
  assert.ok(buf1.every(b => b === 0))
  assert.ok(buf2.every(b => b === 0))
  assert.ok(buf3.every(b => b === 0))
})

