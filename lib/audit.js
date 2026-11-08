/**
 * Append-only JSONL audit trail with independent size-rotated segments and an
 * optional hash chain. Each segment starts with an empty `prev`; reopening an
 * active segment resumes from its last hash. A small lock file serializes
 * writers across plugin instances/processes that share the same audit path.
 *
 * The chain detects edits and deletions in the middle of a segment. It is not
 * an external trust anchor: anyone who can rewrite the log can rebuild a whole
 * chain, and a valid prefix alone cannot prove that tail records were not lost.
 */

import { createHash, randomUUID } from 'node:crypto'
import { readFileSync, promises as fs } from 'node:fs'
import { dirname, join } from 'node:path'
import { homedir } from 'node:os'

const LOCK_STALE_MS = 30_000
const LOCK_WAIT_MS = 30_000
const localQueues = new Map()

export function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

export function defaultAuditFile() {
  return join(dshHome(), 'write-guard', 'audit.jsonl')
}

export function defaultQuarantineDir() {
  return join(dshHome(), 'write-guard', 'quarantine')
}

function recordHash(prev, payload) {
  return createHash('sha256').update(prev).update('\n').update(payload).digest('hex')
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function acquireLock(file) {
  const lockFile = `${file}.lock`
  const started = Date.now()
  while (Date.now() - started < LOCK_WAIT_MS) {
    try {
      const handle = await fs.open(lockFile, 'wx', 0o600)
      await handle.writeFile(`${process.pid}\n${Date.now()}\n`, 'utf8')
      return { handle, lockFile }
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error
      try {
        const stat = await fs.stat(lockFile)
        if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) await fs.unlink(lockFile)
      } catch (statError) {
        if (statError?.code !== 'ENOENT') throw statError
      }
      await sleep(10)
    }
  }
  throw new Error(`timed out waiting for audit lock: ${lockFile}`)
}

async function withLock(file, fn) {
  const previous = localQueues.get(file) ?? Promise.resolve()
  const run = previous.catch(() => {}).then(() => withFileLock(file, fn))
  localQueues.set(file, run)
  try {
    return await run
  } finally {
    if (localQueues.get(file) === run) localQueues.delete(file)
  }
}

async function withFileLock(file, fn) {
  const lock = await acquireLock(file)
  try {
    return await fn()
  } finally {
    try {
      await lock.handle.close()
    } finally {
      await fs.unlink(lock.lockFile).catch(() => {})
    }
  }
}

/** Read only the tail, avoiding an O(file-size) parse on every append. */
async function lastHash(file) {
  let handle
  try {
    handle = await fs.open(file, 'r')
    const stat = await handle.stat()
    if (stat.size === 0) return ''
    const length = Math.min(stat.size, 128 * 1024)
    const buffer = Buffer.alloc(length)
    await handle.read(buffer, 0, length, stat.size - length)
    const lines = buffer.toString('utf8').split('\n').filter((line) => line.trim())
    const row = JSON.parse(lines.at(-1))
    if (typeof row.hash !== 'string' || !/^[0-9a-f]{64}$/.test(row.hash)) {
      throw new Error('last audit record has no valid hash')
    }
    return row.hash
  } catch (error) {
    if (error?.code === 'ENOENT') return ''
    throw new Error(`cannot resume audit chain: ${error instanceof Error ? error.message : String(error)}`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

/**
 * @param {{ file?: string, maxBytes?: number, hashChain?: boolean, logger?: {warn?: Function} }} options
 */
export function createAudit(options = {}) {
  const file = options.file ?? defaultAuditFile()
  const requestedMax = Number(options.maxBytes)
  const maxBytes = Number.isFinite(requestedMax) && requestedMax > 0 ? Math.floor(requestedMax) : 5 * 1024 * 1024
  const hashChain = options.hashChain !== false
  const logger = options.logger
  let chain = Promise.resolve()
  let closePromise = null
  let closed = false

  async function writeRecord(record) {
    try {
      await fs.mkdir(dirname(file), { recursive: true, mode: 0o700 })
      await withLock(file, async () => {
        const previous = hashChain ? await lastHash(file) : ''
        const rotated = await rotateIfNeeded(file, maxBytes)
        const prev = rotated ? '' : previous
        let row = record
        if (hashChain) {
          const hash = recordHash(prev, JSON.stringify(record))
          row = { ...record, prev, hash }
        }
        await fs.appendFile(file, JSON.stringify(row) + '\n', { encoding: 'utf8', mode: 0o600 })
      })
    } catch (error) {
      logger?.warn?.(`write-guard: audit write failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return {
    /** @param {Record<string, unknown>} record */
    append(record) {
      if (closed) return
      const row = { ts: new Date().toISOString(), ...record }
      chain = chain.then(() => writeRecord(row))
    },
    close() {
      if (!closePromise) {
        closed = true
        closePromise = chain
      }
      return closePromise
    },
  }
}

async function rotateIfNeeded(file, maxBytes) {
  try {
    const stat = await fs.stat(file)
    if (stat.size < maxBytes) return false
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    await fs.rename(file, `${file}.${stamp}-${randomUUID()}`)
    return true
  } catch (error) {
    if (error?.code === 'ENOENT') return false
    throw error
  }
}

/**
 * Verify the internal links of one segment and return its head for comparison
 * with an externally protected head, if the operator maintains one.
 * @param {string} file
 * @returns {{ ok: boolean, records: number, brokenAt?: number, reason?: string, head?: string }}
 */
export function verifyChain(file) {
  let text
  try {
    text = readFileSync(file, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return { ok: false, records: 0, reason: 'audit file does not exist' }
    return { ok: false, records: 0, reason: String(error) }
  }
  const lines = text.split('\n').filter((line) => line.trim())
  let prev = ''
  for (let i = 0; i < lines.length; i++) {
    let row
    try {
      row = JSON.parse(lines[i])
    } catch {
      return { ok: false, records: lines.length, brokenAt: i, reason: 'unparseable record' }
    }
    if (typeof row.prev !== 'string' || typeof row.hash !== 'string') {
      return { ok: false, records: lines.length, brokenAt: i, reason: 'record has no hash link' }
    }
    if (row.prev !== prev) {
      return { ok: false, records: lines.length, brokenAt: i, reason: 'prev does not match previous hash' }
    }
    const { prev: _prev, hash: _hash, ...payload } = row
    if (recordHash(prev, JSON.stringify(payload)) !== row.hash) {
      return { ok: false, records: lines.length, brokenAt: i, reason: 'record hash mismatch' }
    }
    prev = row.hash
  }
  return { ok: true, records: lines.length, head: prev }
}
