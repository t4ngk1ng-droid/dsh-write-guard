/**
 * Quarantine store for rejected writes. The payload is written to a directory
 * the agent never works in, with a metadata header, so it can be inspected
 * later without ever touching the workspace. Path traversal is stripped; size
 * is capped; the directory is created owner-only.
 */

import { randomUUID } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { basename, join } from 'node:path'
import { TextDecoder } from 'node:util'

const MAX_PAYLOAD_BYTES = 1024 * 1024

/** Make a filesystem-safe short name from an untrusted path. */
export function safeName(path) {
  const base = basename(String(path).replace(/\\/g, '/')) || 'payload'
  return base.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80) || 'payload'
}

/** Keep attacker-controlled metadata on one bounded header line. */
function headerValue(value, maxLength = 500) {
  return String(value ?? '')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replaceAll(String.fromCharCode(0x2028), '\\u2028')
    .replaceAll(String.fromCharCode(0x2029), '\\u2029')
    .slice(0, maxLength)
}

/**
 * Persist a rejected payload for human review.
 * @param {string} dir absolute quarantine directory
 * @param {{
 *   path: string, decision: string, score: number, sha256: string,
 *   hits: {id:string,title:string,severity:number}[], tool: string, callId?: string,
 * }} record
 * @param {string} content
 * @returns {string|null} the written file, or null when it could not be stored
 */
export function quarantineWrite(dir, record, content) {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const now = new Date().toISOString()
    const stamp = now.replace(/[:.]/g, '-')
    // A timestamp alone collides when two denials for the same path arrive in
    // one millisecond. UUID + wx makes accidental payload overwrite impossible.
    const file = join(dir, `${stamp}-${randomUUID()}-${safeName(record.path)}.txt`)

    const header = [
      '# dsh-write-guard quarantine',
      `# time: ${now}`,
      `# tool: ${headerValue(record.tool, 100)}`,
      `# callId: ${headerValue(record.callId)}`,
      `# target: ${headerValue(record.path, 1000)}`,
      `# decision: ${headerValue(record.decision, 20)} (score ${Number(record.score) || 0})`,
      `# sha256: ${headerValue(record.sha256, 128)}`,
      `# hits: ${record.hits.map((h) => `${headerValue(h.id, 100)}(${Number(h.severity) || 0})`).join(', ') || '(none)'}`,
      '# --- payload begins ---',
      '',
    ].join('\n')

    const room = Math.max(0, MAX_PAYLOAD_BYTES - Buffer.byteLength(header, 'utf8'))
    const truncated = Buffer.byteLength(content, 'utf8') > room
    let body = content
    if (truncated) {
      const marker = '\n# [truncated by write-guard]\n'
      const bodyRoom = Math.max(0, room - Buffer.byteLength(marker, 'utf8'))
      // bodyRoom UTF-16 code units are enough to fill the byte budget; avoid
      // allocating a Buffer for an arbitrarily large rejected payload.
      const buffer = Buffer.from(content.slice(0, bodyRoom), 'utf8')
      body = new TextDecoder().decode(buffer.subarray(0, bodyRoom), { stream: true }) + marker
    }
    writeFileSync(file, header + body, { encoding: 'utf8', mode: 0o600, flag: 'wx' })
    return file
  } catch {
    return null
  }
}
