/**
 * Plugin self-integrity.
 *
 * Fingerprint every first-party file that can affect loading, configuration or
 * operator-run tests/scripts. Only dependency internals, VCS data and package
 * archives are excluded. A missing baseline starts an explicitly visible
 * `baseline` state; a damaged baseline or version change never silently trusts
 * the current tree. Normal upgrades require an operator-approved baseline reset.
 *
 * This is tamper evidence, not a signature system: an attacker who can delete
 * or rewrite both the plugin and its external baseline still controls the root
 * of trust.
 */

import { createHash, randomUUID } from 'node:crypto'
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join, relative } from 'node:path'

const MAX_FILE_BYTES = 4 * 1024 * 1024

/** @param {string} file */
export function fileSha256(file) {
  const buffer = readFileSync(file)
  if (buffer.length > MAX_FILE_BYTES) throw new Error(`file too large: ${file}`)
  return createHash('sha256').update(buffer).digest('hex')
}

/** @param {string} root */
function collectFiles(root) {
  const files = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue
        walk(full)
      } else if (entry.isFile() && !entry.name.endsWith('.tgz')) {
        files.push(full)
      }
    }
  }
  walk(root)
  return files.sort()
}

function validBaseline(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  if (typeof value.version !== 'string' || !value.files || typeof value.files !== 'object' || Array.isArray(value.files)) {
    return false
  }
  return Object.entries(value.files).every(
    ([path, hash]) => path && !path.includes('..') && typeof hash === 'string' && /^[0-9a-f]{64}$/.test(hash),
  )
}

function writeBaseline(baselineFile, version, hashes, count, logger) {
  mkdirSync(dirname(baselineFile), { recursive: true, mode: 0o700 })
  const temp = `${baselineFile}.${process.pid}-${randomUUID()}.tmp`
  try {
    writeFileSync(temp, JSON.stringify({ version, generatedAt: new Date().toISOString(), files: hashes }, null, 2), {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    })
    renameSync(temp, baselineFile)
  } finally {
    if (existsSync(temp)) unlinkSync(temp)
  }
  logger?.warn?.(`write-guard: integrity baseline initialized for ${version} (${count} files); current tree is now trusted`)
}

/**
 * @param {{ root: string, baselineFile: string, version: string, logger?: {warn?: Function, info?: Function} }} options
 * @returns {{ status: 'baseline'|'ok'|'tampered'|'error', changed?: string[], missing?: string[], added?: string[], error?: string, versionChanged?: boolean }}
 */
export function verifyIntegrity(options) {
  const { root, baselineFile, version, logger } = options
  try {
    const hashes = Object.create(null)
    for (const file of collectFiles(root)) {
      hashes[relative(root, file).replace(/\\/g, '/')] = fileSha256(file)
    }

    if (!existsSync(baselineFile)) {
      writeBaseline(baselineFile, version, hashes, Object.keys(hashes).length, logger)
      return { status: 'baseline' }
    }

    let baseline
    try {
      baseline = JSON.parse(readFileSync(baselineFile, 'utf8'))
    } catch (error) {
      const message = `integrity baseline is unreadable: ${error instanceof Error ? error.message : String(error)}`
      logger?.warn?.(`write-guard: ${message}; refusing to replace it`)
      return { status: 'tampered', error: message }
    }
    if (!validBaseline(baseline)) {
      const message = 'integrity baseline has an invalid schema'
      logger?.warn?.(`write-guard: ${message}; refusing to replace it`)
      return { status: 'tampered', error: message }
    }

    const changed = []
    const missing = []
    const added = []
    for (const [rel, hash] of Object.entries(hashes)) {
      if (!Object.hasOwn(baseline.files, rel)) added.push(rel)
      else if (baseline.files[rel] !== hash) changed.push(rel)
    }
    for (const rel of Object.keys(baseline.files)) {
      if (!Object.hasOwn(hashes, rel)) missing.push(rel)
    }
    const versionChanged = baseline.version !== version

    if (versionChanged || changed.length || missing.length || added.length) {
      logger?.warn?.(
        `write-guard: plugin integrity mismatch (version=${baseline.version} -> ${version}; changed=${changed.join(',') || '-'}; missing=${missing.join(',') || '-'}; added=${added.join(',') || '-'})`,
      )
      return { status: 'tampered', changed, missing, added, versionChanged }
    }
    return { status: 'ok' }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    logger?.warn?.(`write-guard: integrity check failed: ${message}`)
    return { status: 'error', error: message }
  }
}

/** Exposed for tests: fingerprint one directory without writing anything. */
export function fingerprint(root) {
  const out = {}
  for (const file of collectFiles(root)) {
    const stat = statSync(file)
    if (!stat.isFile()) continue
    out[relative(root, file).replace(/\\/g, '/')] = fileSha256(file)
  }
  return out
}
