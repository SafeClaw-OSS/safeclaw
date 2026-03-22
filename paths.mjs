// Stable path exports — consumers import these instead of guessing node_modules layout
import { fileURLToPath } from 'node:url'
import { join, dirname } from 'node:path'

const __dirname = dirname(fileURLToPath(import.meta.url))

export const publicDir = join(__dirname, 'public')
