/**
 * Post-write verification.
 *
 * The pre-execute gate cannot see three things: what an `edit` produces after
 * splicing, what a shell append leaves behind, and whether another process
 * changed the file between the gate and the write. Reading the file back
 * covers all three. One tool call may write several files, so each callId is
 * associated with a list of targets rather than a single last-write-winner.
 *
 * Verification is bounded by `maxVerifyBytes`; a file too large to read is
 * reported as `unverified`, never as clean.
 */

import { createHash } from 'node:crypto'
import { closeSync, fstatSync, openSync, readSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'
import { TextDecoder } from 'node:util'

const MAX_PENDING = 256

/**
 * Decode the bytes the same way an editor will. Windows PowerShell's `>` and
 * `Out-File` write UTF-16LE with a BOM (`pwsh` 7 writes UTF-8); decoding that
 * as UTF-8 produces NUL bytes, which the scanner would classify as binary and
 * block even for a clean script. A BOM is authoritative: without one there is
 * no reason to guess UTF-16.
 * @param {Buffer} data
 */
function decodeText(data) {
  if (data.length >= 2 && data[0] === 0xff && data[1] === 0xfe) {
    try {
      return new TextDecoder('utf-16le').decode(data)
    } catch {
      // Fall through to UTF-8 on an engine without the decoder.
    }
  }
  if (data.length >= 2 && data[0] === 0xfe && data[1] === 0xff) {
    try {
      return new TextDecoder('utf-16be').decode(data)
    } catch {
      // Fall through to UTF-8.
    }
  }
  return data.toString('utf8')
}

/**
 * @param {{ maxVerifyBytes: number, logger?: {warn?: Function} }} options
 */
export function createVerifier(options) {
  const maxBytes = options.maxVerifyBytes
  const logger = options.logger
  /** @type {Map<string, { path: string, absPath: string, tool: string, expectedSha: string|null, decision: string }[]>} */
  const pending = new Map()

  function keyFor(exec) {
    const callId = String(exec.callId ?? '')
    if (!callId) return ''
    const session = exec.agent?.session?.id ?? exec.agent?.session?.header?.id ?? ''
    // callId alone is not necessarily unique across tools/sessions.
    return `${session}\0${exec.name ?? ''}\0${callId}`
  }

  /** Store all targets for one call. Returns false instead of failing open. */
  function remember(exec, info) {
    const key = keyFor(exec)
    if (!key) return false
    const items = (Array.isArray(info) ? info : [info]).filter(Boolean)
    if (items.length === 0) return true
    if (!pending.has(key) && pending.size >= MAX_PENDING) return false
    pending.set(key, items)
    return true
  }

  /** Consume the targets before downstream post-hooks run, even if they throw. */
  function take(exec) {
    const key = keyFor(exec)
    if (!key) return []
    const info = pending.get(key) ?? []
    pending.delete(key)
    return info
  }

  /**
   * @param {string} path
   * @param {string} cwd
   * @returns {string} absolute path
   */
  function absolutePath(path, cwd) {
    return isAbsolute(path) ? path : resolve(cwd || process.cwd(), path)
  }

  /**
   * @param {{ path: string, absPath: string, tool: string, expectedSha: string|null }} info
   * @returns {{ status: 'ok'|'tampered'|'unverified'|'missing', size?: number, actualSha?: string, reason?: string, code?: string, text?: string }}
   */
  function verify(info) {
    let fd
    try {
      // Keep one descriptor for stat + bounded read. Besides avoiding a path
      // replacement between statSync/readFileSync, this prevents a growing file
      // from turning into an unbounded allocation after the size check.
      fd = openSync(info.absPath, 'r')
      const before = fstatSync(fd)
      // A directory or device is not a file the command wrote. Treat it as
      // missing instead of "unverified", so a shell redirection that failed
      // with EISDIR is not reported as a possible tamper.
      if (!before.isFile()) return { status: 'missing', reason: 'not a regular file' }
      if (before.size > maxBytes) {
        return { status: 'unverified', reason: `file exceeds maxVerifyBytes (${before.size} > ${maxBytes})`, size: before.size }
      }

      const buffer = Buffer.alloc(before.size + 1)
      let offset = 0
      while (offset < buffer.length) {
        const count = readSync(fd, buffer, offset, buffer.length - offset, offset)
        if (count === 0) break
        offset += count
      }
      const after = fstatSync(fd)
      if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
        return { status: 'tampered', size: after.size, reason: 'file changed while it was being verified' }
      }
      if (offset !== before.size) {
        return { status: 'unverified', size: offset, reason: `short or changing read (${offset} != ${before.size})` }
      }

      const data = buffer.subarray(0, offset)
      const actualSha = createHash('sha256').update(data).digest('hex')
      if (info.expectedSha && actualSha !== info.expectedSha) {
        return {
          status: 'tampered',
          size: data.length,
          actualSha,
          reason: `on-disk hash ${actualSha.slice(0, 12)} != approved ${info.expectedSha.slice(0, 12)}`,
        }
      }
      return { status: 'ok', size: data.length, actualSha, text: decodeText(data) }
    } catch (error) {
      const code = error?.code
      if (code === 'ENOENT') return { status: 'missing', code, reason: 'file does not exist after write' }
      if (code === 'EISDIR' || code === 'ENOTDIR') {
        return { status: 'missing', reason: 'target is not a writable file' }
      }
      logger?.warn?.(`write-guard: verify failed for ${info.path}: ${error instanceof Error ? error.message : String(error)}`)
      return { status: 'unverified', reason: error instanceof Error ? error.message : String(error) }
    } finally {
      if (fd !== undefined) {
        try {
          closeSync(fd)
        } catch {
          // The verification result is more useful than a close error.
        }
      }
    }
  }

  return { remember, take, verify, absolutePath, pending }
}
