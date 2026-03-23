import crypto from 'node:crypto'
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'

// ── Helpers ───────────────────────────────────────────────────────────────────

function base64urlToBuffer(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  return Buffer.from(b64, 'base64')
}

// ── Key generation (P-256 ECDH) ───────────────────────────────────────────────

export async function generateVmKeypair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,  // extractable
    ['deriveKey', 'deriveBits']
  )
  const pk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const sk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
  return { pk, sk }
}

export async function loadOrCreateVmKeypair(dataDir) {
  const pkPath = join(dataDir, 'vm_pk.jwk')
  const skPath = join(dataDir, 'vm_sk.jwk')

  if (existsSync(pkPath) && existsSync(skPath)) {
    const pk = JSON.parse(readFileSync(pkPath, 'utf8'))
    const sk = JSON.parse(readFileSync(skPath, 'utf8'))
    return { pk, sk }
  }

  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  const { pk, sk } = await generateVmKeypair()
  writeFileSync(pkPath, JSON.stringify(pk))
  writeFileSync(skPath, JSON.stringify(sk), { mode: 0o600 })
  return { pk, sk }
}

// ── HKDF key derivation ───────────────────────────────────────────────────────
// HKDF-SHA256(ikm=userKey, salt=vmSk_d_bytes, info="safeclaw-kek") → 32-byte KEK

export async function deriveKEK(userKey, vmSk) {
  // Extract raw private key bytes (d parameter) from JWK as salt
  const salt = base64urlToBuffer(vmSk.d)

  const keyMaterial = await crypto.subtle.importKey(
    'raw', userKey, 'HKDF', false, ['deriveBits']
  )
  const kekBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('safeclaw-kek-v1'),
    },
    keyMaterial,
    256
  )
  return Buffer.from(kekBits)
}

// ── Symmetric encryption (AES-256-GCM) ───────────────────────────────────────
// Wire format: iv(12) || ciphertext+tag

const IV_BYTES = 12

export async function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(IV_BYTES)
  const aesKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['encrypt']
  )
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintext
  )
  return Buffer.concat([iv, Buffer.from(ct)])
}

export async function decrypt(key, sealed) {
  const iv = sealed.subarray(0, IV_BYTES)
  const ct = sealed.subarray(IV_BYTES)
  const aesKey = await crypto.subtle.importKey(
    'raw', key, { name: 'AES-GCM' }, false, ['decrypt']
  )
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ct
    )
    return Buffer.from(plaintext)
  } catch {
    throw new Error('Decryption failed')
  }
}

// ── Envelope encryption ───────────────────────────────────────────────────────

export function generateDEK() {
  return crypto.randomBytes(32)
}

export async function wrapDEK(dek, kek) {
  return encrypt(kek, dek)
}

export async function unwrapDEK(wrapped, kek) {
  return decrypt(kek, wrapped)
}

// ── E2E (P-256 ECDH + HKDF + AES-256-GCM) ───────────────────────────────────
// Wire format: JSON {epk: JWK, iv: base64, ct: base64} → base64-encoded as payload

export async function e2eEncrypt(plaintext, vmPkJwk) {
  // Generate ephemeral P-256 keypair
  const ephemeral = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  )

  // Import server public key
  const serverPub = await crypto.subtle.importKey(
    'jwk', vmPkJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )

  // ECDH → shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPub },
    ephemeral.privateKey,
    256
  )

  // HKDF → AES key
  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveBits']
  )
  const aesKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('safeclaw-e2e'),
    },
    hkdfKey,
    256
  )
  const aesKey = await crypto.subtle.importKey(
    'raw', aesKeyBits, { name: 'AES-GCM' }, false, ['encrypt']
  )

  // Encrypt
  const iv = crypto.randomBytes(12)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintext
  )

  // Export ephemeral public key as JWK
  const epk = await crypto.subtle.exportKey('jwk', ephemeral.publicKey)

  // Wire format: JSON → Buffer
  const wire = JSON.stringify({
    epk,
    iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(ct).toString('base64'),
  })
  return Buffer.from(wire)
}

export async function e2eDecrypt(ciphertext, vmPk, vmSk) {
  // Parse wire format
  const wire = JSON.parse(ciphertext.toString())
  const { epk, iv: ivB64, ct: ctB64 } = wire

  // Import ephemeral public key
  const ephemeralPub = await crypto.subtle.importKey(
    'jwk', epk, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )

  // Import server private key
  const serverPriv = await crypto.subtle.importKey(
    'jwk', vmSk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  )

  // ECDH → shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephemeralPub },
    serverPriv,
    256
  )

  // HKDF → AES key
  const hkdfKey = await crypto.subtle.importKey(
    'raw', sharedBits, 'HKDF', false, ['deriveBits']
  )
  const aesKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode('safeclaw-e2e'),
    },
    hkdfKey,
    256
  )
  const aesKey = await crypto.subtle.importKey(
    'raw', aesKeyBits, { name: 'AES-GCM' }, false, ['decrypt']
  )

  // Decrypt
  const iv = Buffer.from(ivB64, 'base64')
  const ct = Buffer.from(ctB64, 'base64')
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ct
    )
    return Buffer.from(plaintext)
  } catch {
    throw new Error('E2E decryption failed')
  }
}

// ── Response key derivation ───────────────────────────────────────────────────
// HKDF-SHA256(ikm=userKey, salt=nonce, info="safeclaw-response-v1") → 32 bytes

export async function deriveResponseKey(userKey, nonce) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', userKey, 'HKDF', false, ['deriveBits']
  )
  const keyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: Buffer.from(nonce),
      info: new TextEncoder().encode('safeclaw-response-v1'),
    },
    keyMaterial,
    256
  )
  return Buffer.from(keyBits)
}

// ── Zeroize ───────────────────────────────────────────────────────────────────

export function zeroize(...bufs) {
  for (const buf of bufs) buf.fill(0)
}

