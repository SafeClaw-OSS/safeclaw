#!/usr/bin/env node
// SafeClaw — Passkey-encrypted API key vault + credential proxy
// Self-deployable security layer for OpenClaw and other AI agents.

import { createServer } from './lib/server.mjs'
import { createProxy } from './lib/proxy.mjs'
import { loadOrCreateVmKeypair } from './lib/crypto.mjs'

const DATA_DIR = process.env.SAFECLAW_DATA || './data'
const SERVER_PORT = parseInt(process.env.SAFECLAW_PORT || '23294')  // 0x5AFE = "SAFE"
const PROXY_PORT = parseInt(process.env.SAFECLAW_PROXY_PORT || '23295')  // 0x5AFF = "SAFE+1"

const HMAC_SECRET = process.env.SAFECLAW_HMAC_SECRET

async function main() {
  if (!HMAC_SECRET) {
    console.error('[safeclaw] fatal: SAFECLAW_HMAC_SECRET env var is required')
    process.exit(1)
  }

  console.log('[safeclaw] starting...')
  console.log(`[safeclaw] data dir: ${DATA_DIR}`)
  if (process.env.SAFECLAW_INSTANCE_ID) console.log(`[safeclaw] instance: ${process.env.SAFECLAW_INSTANCE_ID}`)
  if (process.env.SAFECLAW_URL) console.log(`[safeclaw] public url: ${process.env.SAFECLAW_URL}`)

  await loadOrCreateVmKeypair(DATA_DIR)

  const proxy = await createProxy({ port: PROXY_PORT, dataDir: DATA_DIR, serverPort: SERVER_PORT })
  const server = await createServer({ port: SERVER_PORT, dataDir: DATA_DIR, proxy, hmacSecret: HMAC_SECRET })

  console.log(`[safeclaw] proxy listening on 127.0.0.1:${PROXY_PORT}`)
  console.log(`[safeclaw] server listening on 0.0.0.0:${SERVER_PORT}`)

  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => {
      console.log(`[safeclaw] ${sig} received, shutting down...`)
      proxy.close()
      server.close()
      process.exit(0)
    })
  }
}

main().catch(err => {
  console.error('[safeclaw] fatal:', err)
  process.exit(1)
})
