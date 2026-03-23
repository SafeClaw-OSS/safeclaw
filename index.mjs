#!/usr/bin/env node
// SafeClaw — Passkey-encrypted API key vault + credential proxy
// Self-deployable security layer for OpenClaw and other AI agents.

import { createServer } from './lib/server.mjs'
import { createProxy } from './lib/proxy.mjs'
import { loadOrCreateVmKeypair } from './lib/crypto.mjs'

const DATA_DIR = process.env.SAFECLAW_DATA || './data'
const SERVER_PORT = parseInt(process.env.SAFECLAW_PORT || '23294')  // 0x5AFE = "SAFE"
const PROXY_PORT = parseInt(process.env.SAFECLAW_PROXY_PORT || '23295')  // 0x5AFF = "SAFE+1"

async function main() {
  console.log('[safeclaw] starting...')
  console.log(`[safeclaw] data dir: ${DATA_DIR}`)

  await loadOrCreateVmKeypair(DATA_DIR)

  const proxy = await createProxy({ port: PROXY_PORT, dataDir: DATA_DIR, serverPort: SERVER_PORT })
  const server = await createServer({ port: SERVER_PORT, dataDir: DATA_DIR, proxy })

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
