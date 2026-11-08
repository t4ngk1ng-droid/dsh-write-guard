/**
 * Alert delivery.
 *
 * Always appends a JSONL alert record next to the audit log. Optionally runs a
 * user-configured command. The message is passed through the `WG_MESSAGE`
 * environment variable — never interpolated into the command line — so an
 * attacker-controlled path cannot become shell syntax.
 *
 * A short per-target cooldown keeps a loop of denied writes from producing
 * hundreds of notifications.
 */

import { spawn } from 'node:child_process'
import { mkdirSync, appendFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

const COOLDOWN_MS = 30_000

/**
 * @param {{ enabled?: boolean, command?: string, minScore?: number, file?: string, logger?: {warn?: Function} }} options
 */
export function createNotifier(options = {}) {
  const enabled = options.enabled === true
  const command = typeof options.command === 'string' ? options.command.trim() : ''
  const minScore = Number.isFinite(options.minScore) ? options.minScore : 70
  const file = options.file ?? join(process.env.DSH_HOME || join(process.env.USERPROFILE || '', '.dsh'), 'write-guard', 'alerts.jsonl')
  const logger = options.logger
  const lastByTarget = new Map()

  function writeAlert(record) {
    try {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 })
      appendFileSync(file, JSON.stringify(record) + '\n', { encoding: 'utf8', mode: 0o600 })
    } catch (error) {
      logger?.warn?.(`write-guard: alert write failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  function runCommand(message) {
    if (!command) return
    try {
      const child = spawn(command, {
        shell: true,
        detached: true,
        stdio: 'ignore',
        env: { ...process.env, WG_MESSAGE: message },
      })
      child.on('error', (error) => {
        logger?.warn?.(`write-guard: notify command failed: ${error.message}`)
      })
      child.unref()
    } catch (error) {
      logger?.warn?.(`write-guard: notify command failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  return {
    /**
     * @param {{ target: string, decision: string, score: number, hits?: {id:string}[], tool: string, quarantineFile?: string|null }} record
     */
    alert(record) {
      // Clean writes are audit events, not alerts; avoid synchronous alert-file
      // I/O on every successful pre-execute call.
      if (record.decision === 'allow') return
      const now = Date.now()
      const key = `${record.decision}:${record.target}`
      const last = lastByTarget.get(key)
      if (last !== undefined && now - last < COOLDOWN_MS) return
      if (lastByTarget.size >= 1024) lastByTarget.delete(lastByTarget.keys().next().value)
      lastByTarget.set(key, now)

      const row = {
        ts: new Date().toISOString(),
        kind: 'write-guard-alert',
        ...record,
      }
      writeAlert(row)

      if (!enabled || record.score < minScore) return
      const message = [
        `[write-guard] ${record.decision.toUpperCase()} ${record.target}`,
        `风险分 ${record.score}`,
        record.hits?.length ? `规则 ${record.hits.map((h) => h.id).join(',')}` : '',
        record.quarantineFile ? `隔离 ${record.quarantineFile}` : '',
      ]
        .filter(Boolean)
        .join(' | ')
      runCommand(message)
    },
  }
}
