/**
 * dsh-write-guard — content-aware write protection for DeepSeek Harness.
 *
 * Two gates on the tool pipeline:
 *
 *   pre-execute  — file writes (`write`/`edit`/`str_replace_editor`) are
 *                  scanned for what they are about to put on disk; shell
 *                  commands (`bash`/`pwsh`) are parsed for the files they
 *                  write. Content rules, file magic, path hazards, entropy,
 *                  and project-level custom rules all feed one 0-100 score.
 *
 *   post-execute — the file is read back: the on-disk hash must match the
 *                  bytes that were approved, and the complete file is scanned
 *                  again so a payload split across several small writes only
 *                  becomes visible at the end.
 *
 * Rejected payloads are quarantined; every decision goes through a hash-chained
 * JSONL audit; the plugin fingerprints its own files at boot.
 *
 * Function plugin — no default export (the Loader unwraps
 * `exports.default ?? exports`; a stray default would discard name/inject/apply).
 *
 * @module dsh-write-guard
 */

import { mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { DEFAULT_CONFIG, normalizeConfig } from './lib/config.js'
import { scanToolCall, extname } from './lib/scanner.js'
import { extractShellWrites, writeCategory } from './lib/shell.js'
import { BINARY_EXTENSIONS, RULES, SCRIPT_EXTENSIONS } from './lib/patterns.js'
import { findRulesFile, loadRulesFile, mergeRules, RULES_FILE_NAME } from './lib/rules-file.js'
import { createAudit, defaultAuditFile, defaultQuarantineDir, dshHome, verifyChain } from './lib/audit.js'
import { createNotifier } from './lib/notify.js'
import { createVerifier } from './lib/postwrite.js'
import { quarantineWrite } from './lib/quarantine.js'
import { verifyIntegrity } from './lib/integrity.js'

export const name = 'write-guard'
/**
 * `tools` carries the gates and the tools, so it stays required — a profile
 * without it should fail loudly rather than leave writes unguarded.
 * `webServer` + `connection` only carry the settings-panel route and must be
 * optional: a profile that serves the UI over file:// has no web server, and
 * requiring it there would keep the whole guard from activating.
 */
export const inject = ['tools', 'webServer', 'connection']

const WRITE_TOOL_NAMES = new Set(['write', 'edit', 'str_replace_editor', 'apply_patch'])
const SHELL_TOOL_NAMES = new Set(['bash', 'pwsh', 'powershell', 'cmd'])

/**
 * Shell write sources whose bytes the static parser did not read: pipeline
 * output, run-time values and archive contents. They always follow
 * `shellUnknownPolicy` instead of being treated as an ordinary log redirect.
 */
const UNKNOWN_CONTENT_SOURCES = new Set([
  'download',
  'extract',
  'tee',
  'echo',
  'printf',
  'out-file',
  'set-content',
  'add-content',
  'set-item',
  'dotnet-write',
  'new-item',
  'stdin-script',
])

/**
 * The registry accepts plain tool definitions. This helper produces the same
 * shape `defineTool` does, without importing `@deepseek-ai/dsh-tools` — a
 * plugin installed into a profile cannot resolve the runtime package from
 * its own node_modules, and a static import would fail at load time.
 * Parameters are already JSON Schema here, so no DSL compilation is needed.
 */
function defineTool(options) {
  if (options.timeoutMs !== undefined && (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0)) {
    throw new Error(`defineTool(${options.name}): timeoutMs must be a positive finite number`)
  }
  return {
    name: options.name,
    description: options.description,
    parameters: options.parameters,
    output: {
      schema: options.output.schema,
      render: (args, value) => options.output.render(value, args),
    },
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.isConcurrencySafe
      ? { isConcurrencySafe: (args) => options.isConcurrencySafe(args) }
      : {}),
    async execute(args, exec) {
      return options.execute(args, exec)
    },
  }
}

/** Ring buffer of recent decisions for `write_guard_status`. */
function createRecent(capacity = 50) {
  const items = []
  return {
    push(item) {
      items.unshift(item)
      if (items.length > capacity) items.length = capacity
    },
    list() {
      return items.slice()
    },
  }
}

/** deny > ask > allow */
function worst(a, b) {
  const rank = { allow: 0, ask: 1, deny: 2 }
  return rank[b] > rank[a] ? b : a
}

function escalates(previous, next) {
  const rank = { allow: 0, ask: 1, deny: 2 }
  return rank[next] > rank[previous]
}

/** Switches `write_guard_config` accepts, grouped for the no-argument listing. */
const SWITCH_GROUPS = Object.freeze({
  '判定': ['mode', 'blockThreshold', 'askThreshold', 'onScannerError'],
  '扫描预算': ['maxScanBytes', 'maxContentBytes', 'maxVerifyBytes', 'truncatePolicy'],
  '路径': ['scriptPolicy', 'docPolicy', 'blockBinaries', 'ignorePaths'],
  '内容检测': ['entropy', 'entropyThreshold', 'entropyMinLength', 'homoglyph', 'contentChecks'],
  'Shell 写入': ['shellGuard', 'shellUnknownPolicy', 'shellChecks'],
  '写后校验': ['verifyWrites', 'verifyPolicy'],
  '证据与通知': ['quarantine', 'audit', 'auditHashChain', 'integrity', 'notify', 'notifyMinScore'],
})

/** Runtime edits need a restart to rebuild these collaborators. */
// Only switches whose collaborator is built at mount. `quarantine` is read
// live on every deny, so it belongs to the immediate group; `quarantineDir` is
// resolved once and does not.
const RESTART_ONLY = new Set(['quarantineDir', 'audit', 'auditFile', 'auditMaxBytes', 'auditHashChain', 'integrity', 'notify', 'notifyCommand', 'notifyMinScore'])

/**
 * Merge a `set` payload into the stored overrides. Nested objects merge key by
 * key so flipping one category does not reset its siblings.
 * @param {Record<string, unknown>} current
 * @param {Record<string, unknown>} set
 * @param {string[]} clear
 */
function mergeRuntime(current, set, clear) {
  const next = { ...current }
  for (const key of clear) delete next[key]
  for (const [key, value] of Object.entries(set)) {
    const nested = value && typeof value === 'object' && !Array.isArray(value)
    // Object.create(null) semantics: assigning through a plain object would
    // let `__proto__` reach the legacy setter and swap the prototype.
    if (nested && next[key] && typeof next[key] === 'object' && !Array.isArray(next[key])) {
      next[key] = { ...next[key], ...value }
    } else {
      next[key] = value
    }
  }
  return next
}

/** Switch names that may appear in a runtime override. */
const RUNTIME_KEYS = new Set(Object.keys(DEFAULT_CONFIG))
const CHECK_GROUP_KEYS = {
  shellChecks: new Set(Object.keys(DEFAULT_CONFIG.shellChecks)),
  contentChecks: new Set(Object.keys(DEFAULT_CONFIG.contentChecks)),
}
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * Reject anything the panel or the tool is not allowed to write before it can
 * reach the merge. Without this, a direct POST could add arbitrary keys to the
 * override file and, through `__proto__`, swap a merged object's prototype.
 * @param {Record<string, unknown>} set
 * @param {string[]} clear
 */
function assertRuntimePatch(set, clear) {
  const bad = (message) => {
    throw Object.assign(new Error(message), { statusCode: 400 })
  }
  for (const key of clear) {
    if (FORBIDDEN_KEYS.has(key) || !RUNTIME_KEYS.has(key)) bad(`unknown clear key: ${key}`)
  }
  for (const [key, value] of Object.entries(set)) {
    if (FORBIDDEN_KEYS.has(key) || !RUNTIME_KEYS.has(key)) bad(`unknown set key: ${key}`)
    const allowed = CHECK_GROUP_KEYS[key]
    if (!allowed) continue
    if (!value || typeof value !== 'object' || Array.isArray(value)) bad(`${key} must be an object`)
    for (const [name, enabled] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(name) || !allowed.has(name)) bad(`unknown ${key} key: ${name}`)
      if (typeof enabled !== 'boolean') bad(`${key}.${name} must be a boolean`)
    }
  }
}

/** Switches whose effective value differs from the shipped default. */
function changedFromDefault(config) {
  const changed = {}
  for (const [key, value] of Object.entries(config)) {
    if (key === 'shellChecks' || key === 'contentChecks') {
      const off = Object.entries(value).filter(([, on]) => on === false).map(([name]) => name)
      if (off.length > 0) changed[key] = off
    } else if (JSON.stringify(value) !== JSON.stringify(DEFAULT_CONFIG[key])) {
      changed[key] = value
    }
  }
  return changed
}

/** @param {Record<string, any>} config */
function publicConfig(config) {
  return {
    mode: config.mode,
    thresholds: { block: config.blockThreshold, ask: config.askThreshold },
    scriptPolicy: config.scriptPolicy,
    docPolicy: config.docPolicy,
    blockBinaries: config.blockBinaries,
    shellGuard: config.shellGuard,
    shellUnknownPolicy: config.shellUnknownPolicy,
    verifyWrites: config.verifyWrites,
    verifyPolicy: config.verifyPolicy,
    entropy: config.entropy,
    homoglyph: config.homoglyph,
    quarantine: config.quarantine,
    audit: config.audit,
    integrity: config.integrity,
    notify: config.notify,
    shellChecks: config.shellChecks,
    contentChecks: config.contentChecks,
    changed: changedFromDefault(config),
  }
}

function renderConfig(value) {
  if (!value?.ok) return `write-guard: 配置未修改：${value?.error ?? 'unknown error'}`
  const c = value.config
  const off = (map) => Object.entries(map).filter(([, on]) => on === false).map(([k]) => k)
  const lines = [
    `模式 ${c.mode}｜拦截 ≥${c.thresholds.block}｜转人工 ≥${c.thresholds.ask}`,
    `shell 细节：${off(c.shellChecks).join(', ') || '全部开启'}`,
    `内容检测：${off(c.contentChecks).join(', ') || '全部开启'}`,
  ]
  if (value.file) lines.push(`已写入 ${value.file}`)
  if (value.available) {
    lines.push('可改开关：' + Object.entries(value.available).map(([g, keys]) => `${g}=${keys.join('/')}`).join('；'))
  }
  const changed = Object.keys(c.changed)
  lines.push(changed.length ? `偏离默认：${changed.join(', ')}` : '全部为默认值')
  return lines.join('\n')
}

/** Grouped switch names, for the listing returned when no arguments are given. */
function availableSwitches() {
  const out = {}
  for (const [group, keys] of Object.entries(SWITCH_GROUPS)) out[group] = [...keys]
  return out
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Record<string, unknown>} rawConfig
 */
export function apply(ctx, rawConfig = {}) {
  // Runtime overrides written by `write_guard_config`. They sit on top of the
  // loader config so a switch can be flipped without editing the profile.
  const runtimeConfigFile = join(dshHome(), 'write-guard', 'config.json')
  let runtimeConfig = {}
  try {
    const parsed = JSON.parse(readFileSync(runtimeConfigFile, 'utf8'))
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) runtimeConfig = parsed
  } catch {
    // Missing or malformed: the loader config stands.
  }
  const mergeConfig = () => normalizeConfig({ ...rawConfig, ...runtimeConfig })
  let config = mergeConfig()
  const builtinRules = RULES

  /**
   * Persist overrides and rebuild the live config. Shared by the
   * `write_guard_config` tool and the settings panel route so both write the
   * same file through the same merge.
   * @param {Record<string, unknown>} set
   * @param {string[]} clear
   */
  const saveRuntimeConfig = (set, clear) => {
    assertRuntimePatch(set, clear)
    const next = mergeRuntime(runtimeConfig, set, clear)
    mkdirSync(dirname(runtimeConfigFile), { recursive: true, mode: 0o700 })
    const temp = `${runtimeConfigFile}.${process.pid}.tmp`
    writeFileSync(temp, JSON.stringify(next, null, 2), { encoding: 'utf8', mode: 0o600 })
    renameSync(temp, runtimeConfigFile)
    runtimeConfig = next
    config = mergeConfig()
    return { ok: true, config: publicConfig(config), file: runtimeConfigFile, applied: 'immediately' }
  }

  const audit = config.audit
    ? createAudit({
        file: config.auditFile || defaultAuditFile(),
        maxBytes: config.auditMaxBytes,
        hashChain: config.auditHashChain,
        logger: ctx.logger,
      })
    : null
  const quarantineDir = config.quarantineDir || defaultQuarantineDir()
  const notifier = createNotifier({
    enabled: config.notify,
    command: config.notifyCommand,
    minScore: config.notifyMinScore,
    file: join(dshHome(), 'write-guard', 'alerts.jsonl'),
    logger: ctx.logger,
  })
  const verifier = createVerifier({ maxVerifyBytes: config.maxVerifyBytes, logger: ctx.logger })
  const recent = createRecent()
  const stats = {
    scanned: 0,
    allowed: 0,
    asked: 0,
    denied: 0,
    quarantined: 0,
    shellWrites: 0,
    verified: 0,
    tampered: 0,
    rescanBlocked: 0,
  }

  // --- self integrity ------------------------------------------------------
  const pluginRoot = dirname(fileURLToPath(import.meta.url))
  let integrity = { status: 'disabled' }
  if (config.integrity) {
    integrity = verifyIntegrity({
      root: pluginRoot,
      baselineFile: join(dshHome(), 'write-guard', 'integrity.json'),
      version: readVersion(),
      logger: ctx.logger,
    })
  }

  // --- rules ---------------------------------------------------------------
  const ruleCache = new Map() // file -> { mtimeMs, rules }
  let lastRulesFile = ''
  // Walking up from cwd on every write is a stat storm; cache the discovery
  // for a few seconds and let the mtime check below handle edits.
  let discovery = { cwd: '', file: null, at: 0 }

  function discoverRulesFile(cwd) {
    if (config.rulesFile) return resolve(config.rulesFile)
    const now = Date.now()
    if (discovery.cwd === cwd && now - discovery.at < 5000) return discovery.file
    const file = findRulesFile(cwd)
    discovery = { cwd, file, at: now }
    return file
  }

  function effectiveRules(cwd) {
    const file = discoverRulesFile(cwd)
    if (!file) return builtinRules
    lastRulesFile = file
    try {
      const stat = statSync(file)
      const cached = ruleCache.get(file)
      if (cached && (!config.watchRules || cached.mtimeMs === stat.mtimeMs)) return cached.rules
      const { rules } = loadRulesFile(file)
      const merged = mergeRules(builtinRules, rules)
      ruleCache.set(file, { mtimeMs: stat.mtimeMs, rules: merged })
      ctx.logger?.info?.(`write-guard: loaded ${rules.length} custom rule(s) from ${file}`)
      return merged
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      ctx.logger?.warn?.(`write-guard: rules file rejected (${message}); keeping previous rules`)
      const cached = ruleCache.get(file)
      if (cached) return cached.rules
      // With no known-good project policy, fail closed instead of silently
      // dropping every custom constraint because the file is malformed.
      throw new Error(`rules file rejected: ${message}`)
    }
  }

  function readVersion() {
    try {
      const pkg = JSON.parse(readFileSync(join(pluginRoot, 'package.json'), 'utf8'))
      return String(pkg.version ?? '0.0.0')
    } catch {
      return '0.0.0'
    }
  }

  if (config.mode === 'off') {
    ctx.logger?.info?.('write-guard: disabled by config (mode=off)')
  } else if (config.mode === 'dry-run') {
    ctx.logger?.info?.('write-guard: dry-run — decisions are recorded, never enforced')
  }

  // ---------------------------------------------------------------------
  // Shared bookkeeping for a scan result
  // ---------------------------------------------------------------------
  function finalize(exec, scan, source) {
    stats.scanned++
    if (scan.decision === 'allow') stats.allowed++
    else if (scan.decision === 'ask') stats.asked++
    else stats.denied++

    const callId = String(exec.callId ?? '')
    const record = {
      event: 'write-decision',
      tool: exec.name,
      callId,
      source,
      target: scan.path,
      decision: scan.decision,
      dryRun: scan.dryRun,
      score: scan.score,
      bytes: scan.bytes,
      truncated: scan.truncated,
      binary: scan.binary,
      normalized: scan.normalized,
      magic: scan.magic?.id ?? null,
      sha256: scan.sha256,
      hits: scan.hits.map((h) => ({ id: h.id, severity: h.severity, title: h.title })),
    }

    if (!scan.dryRun && scan.decision === 'deny' && config.quarantine && scan.content) {
      const stored = quarantineWrite(quarantineDir, { ...record, path: scan.path }, scan.content)
      if (stored) {
        stats.quarantined++
        record.quarantineFile = stored
        ctx.logger?.warn?.(`write-guard: blocked ${scan.path} (score ${scan.score}); payload saved to ${stored}`)
      }
    }

    recent.push({
      at: new Date().toISOString(),
      source,
      tool: exec.name,
      target: scan.path,
      decision: scan.decision,
      score: scan.score,
      hits: scan.hits.map((h) => h.id),
      quarantineFile: record.quarantineFile ?? null,
    })
    audit?.append(record)
    notifier.alert({
      target: scan.path,
      decision: scan.decision,
      score: scan.score,
      tool: exec.name,
      hits: scan.hits,
      quarantineFile: record.quarantineFile ?? null,
    })
    return record
  }

  // ---------------------------------------------------------------------
  // Pre-execute gate
  // ---------------------------------------------------------------------
  ctx.on('tools/pre-execute', async (exec, next) => {
    // `off` must be a real off switch: no rules file loading, no scanner
    // failure path, no shell-unknown policy. Returning before any work also
    // keeps a malformed project rules file from turning into an `ask`.
    if (config.mode === 'off') return next()
    const cwd = exec.agent?.session?.header?.cwd ?? process.cwd()
    let verdict = 'allow'
    let reason = ''
    /** @type {{ path: string, cwd: string, absPath: string, tool: string, expectedSha: string|null, decision: string, allowAbsent: boolean }[]} */
    const pendingVerify = []
    const rememberWrite = (write, tool, expectedSha, decision) => {
      if (!config.verifyWrites || config.mode === 'dry-run' || decision === 'deny') return
      // A dynamic target (variable, substitution, glob) is not the path Node
      // can open later; verifying it would report the wrong file as missing.
      if (write.dynamic) return
      const absPath = verifier.absolutePath(write.path, cwd)
      const previous = pendingVerify.find((item) => item.absPath === absPath)
      if (previous) {
        if (!write.skipVerify) previous.allowAbsent = false
        return
      }
      pendingVerify.push({ path: write.path, cwd, absPath, tool, expectedSha, decision, allowAbsent: !!write.skipVerify })
    }

    try {
      // --- direct file writes ---------------------------------------------
      if (WRITE_TOOL_NAMES.has(exec.name)) {
        const rules = effectiveRules(cwd)
        const scan = scanToolCall({ name: exec.name, args: exec.arguments, cwd }, config, rules)
        if (scan) {
          finalize(exec, scan, 'tool')
          if (scan.decision !== 'allow' || scan.dryRun) {
            verdict = worst(verdict, scan.dryRun ? 'allow' : scan.decision)
            reason = reason || scan.reason
          }
          if (scan.path && exec.name !== 'apply_patch') {
            // An approved `ask` still needs verification. Only a plain `write`
            // has a one-to-one relation between the scanned string and the
            // expected on-disk bytes; edits verify by full rescan. Multi-file
            // apply_patch needs per-operation targets and is not guessed here.
            rememberWrite(
              { path: scan.path },
              exec.name,
              exec.name === 'write' ? scan.sha256 || null : null,
              scan.decision,
            )
          }
        }
      }

      // --- shell writes ----------------------------------------------------
      if (config.shellGuard && SHELL_TOOL_NAMES.has(exec.name)) {
        const extracted = extractShellWrites(exec.name, exec.arguments, cwd)
        if (extracted) {
          const rules = effectiveRules(cwd)
          // Use one session-relative name for policy, audit and readback.
          const inSession = (w) => w.baseDir && !isAbsolute(w.path)
            ? { ...w, path: relative(cwd, resolve(w.baseDir, w.path)) || '.' } : w
          // A category switched off is not reported at all: the write passes
          // unscanned, which is why the switches default to on.
          const enabled = (w) => config.shellChecks[writeCategory(w.source)] !== false

          for (const candidate of extracted.known) {
            if (!enabled(candidate)) continue
            const write = inSession(candidate)
            const scan = scanToolCall(
              { name: 'write', args: { file_path: write.path, content: write.content }, cwd },
              config,
              rules,
            )
            if (!scan) continue
            // The content is literal, but the target is resolved at run time.
            // Extension-based policy (bare `.ps1`, binaries) cannot see the
            // real suffix, so a clean payload still needs confirmation.
            if (write.dynamic && scan.decision === 'allow') {
              scan.decision = 'ask'
              scan.score = Math.max(scan.score, config.askThreshold)
              scan.reason = `write-guard 拦截（ask，风险分 ${scan.score}）：${write.path} 的路径含动态变量或执行目录不确定，无法确认最终目标`
            }
            finalize(exec, scan, `shell:${write.source}`)
            stats.shellWrites++
            if (scan.decision !== 'allow' && !scan.dryRun) {
              verdict = worst(verdict, scan.decision)
              reason = reason || scan.reason
            }
            rememberWrite(write, exec.name, null, scan.decision)
          }

          for (const candidate of extracted.unknown) {
            if (!enabled(candidate)) continue
            const write = inSession(candidate)
            const ext = extname(write.path)
            const riskyPath = BINARY_EXTENSIONS.has(ext) || SCRIPT_EXTENSIONS.has(ext)
            const needsApproval = write.dynamic || riskyPath || UNKNOWN_CONTENT_SOURCES.has(write.source)
            const decision = needsApproval ? (config.shellUnknownPolicy === 'ask' ? 'ask' : 'allow') : 'allow'
            stats.scanned++
            stats.shellWrites++
            if (decision === 'ask') stats.asked++
            else stats.allowed++

            const record = {
              event: 'shell-write',
              tool: exec.name,
              callId: String(exec.callId ?? ''),
              source: `shell:${write.source}`,
              target: write.path,
              decision,
              dryRun: config.mode === 'dry-run',
              score: needsApproval ? config.askThreshold : 0,
              reason: needsApproval
                ? write.dynamic
                  ? `无法检查写入内容（${write.source}，路径含动态变量或执行目录不确定）`
                  : `无法检查写入内容（${write.source}）`
                : '低风险目标',
            }
            audit?.append(record)
            recent.push({
              at: new Date().toISOString(),
              source: `shell:${write.source}`,
              tool: exec.name,
              target: write.path,
              decision,
              score: record.score,
              hits: [],
              quarantineFile: null,
            })
            if (decision === 'ask' && !record.dryRun) {
              verdict = worst(verdict, 'ask')
              reason = reason || `write-guard：${write.path} 的写入内容来自 ${write.source}，无法静态检查，需要确认`
            }
            // Extraction targets are directories and need a recursive scanner;
            // file-producing redirects/downloads can be verified directly.
            if (write.source !== 'extract' && !write.dynamic) rememberWrite(write, exec.name, null, decision)
          }
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      ctx.logger?.warn?.(`write-guard: scan failed for ${exec.name}: ${message}`)
      // Fail-open applies to the failed scan only; it must not erase a deny
      // already established for another target in the same tool call.
      if (config.mode !== 'dry-run' && config.onScannerError !== 'allow') {
        verdict = worst(verdict, 'ask')
        reason = reason || `write-guard 扫描失败（${message}），需要人工确认本次写入`
      }
    }

    if (pendingVerify.length > 0 && verdict !== 'deny') {
      const remembered = verifier.remember(exec, pendingVerify)
      if (!remembered && config.verifyPolicy === 'block') {
        verdict = 'deny'
        reason = 'write-guard：无法关联写后校验（缺少 callId 或待校验队列已满），本次写入未执行'
      } else if (!remembered) {
        ctx.logger?.warn?.(`write-guard: post-write verification could not be tracked for ${exec.name}`)
      }
    }
    if (verdict === 'deny') verifier.take(exec) // clear any stale entry for a reused id
    if (verdict === 'allow') return next()
    return { kind: verdict, reason: reason || 'write-guard: blocked' }
  })

  // ---------------------------------------------------------------------
  // Post-execute verification
  // ---------------------------------------------------------------------
  ctx.on('tools/post-execute', async (exec, result, next) => {
    // Consume before running downstream hooks so a throw cannot leave a stale
    // callId entry that a later invocation accidentally picks up.
    const infos = verifier.take(exec)
    const decision = await next()
    if (infos.length === 0 || decision?.kind === 'block') return decision
    // A failed tool (including a rejected `ask`) usually wrote nothing, so a
    // missing target is expected and must not replace the real error. If the
    // file does exist, the command ran partially and still gets verified: a
    // failing command must not become a way to skip the post-write scan.
    const failed = result?.isError === true

    let blocked = null
    const block = (text) => {
      if (config.verifyPolicy === 'block' && !blocked) {
        blocked = { kind: 'block', feedback: [{ type: 'text', text }] }
      }
    }

    for (const info of infos) {
      const verified = verifier.verify(info)
      stats.verified++

      // Only the "nothing was written" case is skipped for a failed tool.
      // An existing file still goes through the hash and full-file scan.
      if (verified.status === 'missing' && (failed || (info.allowAbsent && verified.code === 'ENOENT'))) {
        audit?.append({
          event: 'write-verify',
          tool: exec.name,
          callId: String(exec.callId ?? ''),
          target: info.path,
          status: 'skipped',
          reason: failed ? 'tool result is an error and no file exists' : 'short-circuited shell branch and no file exists',
        })
        continue
      }

      if (verified.status !== 'ok') {
        if (verified.status === 'tampered') stats.tampered++
        audit?.append({
          event: 'write-verify',
          tool: exec.name,
          callId: String(exec.callId ?? ''),
          target: info.path,
          status: verified.status,
          expected: info.expectedSha?.slice(0, 16) ?? null,
          actual: verified.actualSha?.slice(0, 16) ?? null,
          size: verified.size,
          reason: verified.reason,
        })
        notifier.alert({
          target: info.path,
          decision: 'deny',
          score: config.blockThreshold,
          tool: exec.name,
          hits: [{ id: `postwrite-${verified.status}` }],
        })
        block(
          verified.status === 'tampered'
            ? `write-guard: ${info.path} 落盘后的哈希或读取状态与批准内容不一致（${verified.reason}）。文件已落盘且未自动回滚，请人工核对。`
            : verified.status === 'missing' && SHELL_TOOL_NAMES.has(info.tool)
              ? `write-guard: ${info.path} 的写后校验未完成（文件不存在）。shell 命令可能失败，或路径在 shell 自己的命名空间（/tmp、$env:TEMP）中被解析；请核对命令与实际落盘位置。`
              : `write-guard: ${info.path} 的写后校验未完成（${verified.status}：${verified.reason}）。文件已经历写入操作且未自动删除或回滚，请人工核对当前内容。`,
        )
        continue
      }

      // Full-file rescan: expand the scan budget to the already bounded read
      // size. Otherwise "full rescan" silently becomes another prefix scan for
      // files larger than maxScanBytes.
      try {
        const cwd = info.cwd
        const rescanConfig = {
          ...config,
          maxScanBytes: Math.max(config.maxScanBytes, verified.size ?? 0),
          maxContentBytes: Math.max(config.maxContentBytes, verified.size ?? 0),
        }
        const rescan = scanToolCall(
          { name: 'write', args: { file_path: info.path, content: verified.text ?? '' }, cwd },
          rescanConfig,
          effectiveRules(cwd),
        )
        // Only escalate risk that was not present in the pre-execute decision.
        // A .ps1 that was already reviewed as `ask` must not be blocked again
        // merely because the post-pass sees the same script extension.
        if (rescan && escalates(info.decision, rescan.decision)) {
          stats.rescanBlocked++
          let quarantineFile = null
          const record = {
            event: 'write-rescan',
            tool: exec.name,
            callId: String(exec.callId ?? ''),
            target: info.path,
            decision: rescan.decision,
            score: rescan.score,
            sha256: verified.actualSha,
            hits: rescan.hits.map((h) => ({ id: h.id, severity: h.severity, title: h.title })),
            fullBytes: verified.size,
          }
          if (config.quarantine && verified.text) {
            quarantineFile = quarantineWrite(
              quarantineDir,
              { ...record, path: info.path },
              verified.text,
            )
            record.quarantineFile = quarantineFile
          }
          audit?.append(record)
          notifier.alert({
            target: info.path,
            decision: rescan.decision,
            score: rescan.score,
            tool: exec.name,
            hits: rescan.hits,
            quarantineFile,
          })
          block(
            `write-guard: ${info.path} 的完整文件出现新的${rescan.decision === 'deny' ? '高危' : '待复核'}内容` +
              `（${rescan.hits.map((h) => h.id).join(',') || '路径/字节检查'}，风险分 ${rescan.score}）。` +
              '文件已经落盘且未自动删除或回滚，请停止后续执行并人工核对。',
          )
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        ctx.logger?.warn?.(`write-guard: post-write rescan failed for ${info.path}: ${message}`)
        audit?.append({
          event: 'write-verify',
          tool: exec.name,
          callId: String(exec.callId ?? ''),
          target: info.path,
          status: 'unverified',
          reason: `post-write rescan failed: ${message}`,
        })
        block(`write-guard: ${info.path} 的写后全文扫描失败（${message}）。文件已落盘，请人工核对。`)
      }
    }

    return blocked ?? decision
  })

  // ---------------------------------------------------------------------
  // Tools
  // ---------------------------------------------------------------------
  ctx.tools.register(
    defineTool({
      name: 'write_guard_scan',
      description:
        'Scan a piece of text (or a file path string) with the write-guard engine without writing anything. Returns the verdict (allow/ask/deny), a 0-100 risk score, matched rule ids with severities, entropy findings, and whether the content was truncated. Use it before writing an unfamiliar script, or to explain why a write was blocked.',
      parameters: {
        type: 'object',
        properties: {
          text: { type: 'string', description: 'Content to inspect.' },
          path: {
            type: 'string',
            description: 'Optional target path; its extension participates in the verdict (.ps1/.exe etc.).',
          },
        },
        required: ['text'],
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            decision: { type: 'string', enum: ['allow', 'ask', 'deny'] },
            score: { type: 'integer' },
            hits: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  id: { type: 'string' },
                  category: { type: 'string' },
                  severity: { type: 'integer' },
                  title: { type: 'string' },
                },
              },
            },
            entropy: { type: 'array', items: { type: 'object', additionalProperties: true } },
            truncated: { type: 'boolean' },
            bytes: { type: 'integer' },
            reason: { type: 'string' },
          },
        },
        render: (value) => [{ type: 'text', text: formatScan(value) }],
      },
      timeoutMs: 10_000,
      isConcurrencySafe: () => true,
      async execute(args, exec) {
        const text = String(args?.text ?? '')
        const path = typeof args?.path === 'string' && args.path ? args.path : 'scan.txt'
        // Project rules are discovered from the session cwd, not from whatever
        // directory the host process happens to run in.
        const cwd = exec?.agent?.session?.header?.cwd ?? process.cwd()
        const result = scanToolCall(
          { name: 'write', args: { file_path: path, content: text }, cwd },
          config,
          effectiveRules(cwd),
        )
        if (!result) {
          return {
            decision: 'allow',
            score: 0,
            hits: [],
            entropy: [],
            truncated: false,
            bytes: Buffer.byteLength(text),
            reason: '被 ignorePaths 排除',
          }
        }
        return {
          decision: result.decision,
          score: result.score,
          hits: result.hits,
          entropy: result.entropy,
          truncated: result.truncated,
          bytes: result.bytes,
          reason: result.reason || '未命中规则',
        }
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'write_guard_status',
      description:
        'Report the write-guard configuration, live counters, rule sources, self-integrity status, and the most recent blocked/asked writes (including quarantine file paths). Read-only.',
      parameters: { type: 'object', properties: {} },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            mode: { type: 'string' },
            stats: { type: 'object', additionalProperties: true },
            rules: { type: 'object', additionalProperties: true },
            integrity: { type: 'object', additionalProperties: true },
            recent: { type: 'array', items: { type: 'object', additionalProperties: true } },
            auditFile: { type: 'string' },
            quarantineDir: { type: 'string' },
          },
        },
        render: (value) => [{ type: 'text', text: formatStatus(value) }],
      },
      timeoutMs: 5_000,
      isConcurrencySafe: () => true,
      async execute() {
        return {
          mode: config.mode,
          blockThreshold: config.blockThreshold,
          askThreshold: config.askThreshold,
          scriptPolicy: config.scriptPolicy,
          docPolicy: config.docPolicy,
          shellGuard: config.shellGuard,
          verifyWrites: config.verifyWrites,
          stats,
          rules: {
            builtin: builtinRules.length,
            file: lastRulesFile || `(未找到 ${RULES_FILE_NAME})`,
            customLoaded: [...ruleCache.values()].reduce((n, entry) => n + (entry.rules.length - builtinRules.length), 0),
          },
          integrity,
          recent: recent.list(),
          auditFile: config.audit ? config.auditFile || defaultAuditFile() : '',
          quarantineDir: config.quarantine ? quarantineDir : '',
        }
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'write_guard_config',
      description:
        'Read or change write-guard switches at runtime. Call with no arguments to list the current settings and every available switch. Call with `set` (and optionally `clear`) to change them: values are merged, written to <DSH_HOME>/write-guard/config.json, and applied immediately. Setting a nested object only changes the keys you pass, so flipping one category leaves the others alone. Changes to audit/quarantine/notify/integrity only take effect after a restart.',
      parameters: {
        type: 'object',
        properties: {
          set: {
            type: 'object',
            additionalProperties: true,
            description:
              'Switches to change, e.g. {"shellChecks":{"extract":false}} or {"mode":"dry-run"}. Nested objects are merged key by key.',
          },
          clear: {
            type: 'array',
            items: { type: 'string' },
            description: 'Switch names to revert to the shipped default, e.g. ["shellChecks"].',
          },
        },
      },
      output: {
        schema: { type: 'object', additionalProperties: true },
        render: (value) => [{ type: 'text', text: renderConfig(value) }],
      },
      timeoutMs: 5_000,
      isConcurrencySafe: () => false,
      async execute(args) {
        const set = args?.set && typeof args.set === 'object' && !Array.isArray(args.set) ? args.set : null
        const clear = Array.isArray(args?.clear) ? args.clear.map(String) : []
        if (!set && clear.length === 0) {
          return { ok: true, config: publicConfig(config), available: availableSwitches() }
        }
        try {
          return saveRuntimeConfig(set ?? {}, clear)
        } catch (error) {
          return { ok: false, error: error instanceof Error ? error.message : String(error) }
        }
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'write_guard_reload',
      description:
        'Re-read the project rules file (`write-guard.rules.json`) and report how many rules are active. Use after editing the rules file.',
      parameters: { type: 'object', properties: {} },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            ok: { type: 'boolean' },
            file: { type: 'string' },
            builtin: { type: 'integer' },
            total: { type: 'integer' },
            error: { type: 'string' },
          },
        },
        render: (value) => [
          {
            type: 'text',
            text: value.ok
              ? `write-guard: ${value.total} 条规则生效（内置 ${value.builtin}，文件 ${value.file}）`
              : `write-guard: 规则加载失败：${value.error}`,
          },
        ],
      },
      timeoutMs: 5_000,
      isConcurrencySafe: () => true,
      async execute(args, exec) {
        const cwd = exec?.agent?.session?.header?.cwd ?? process.cwd()
        const file = config.rulesFile ? resolve(config.rulesFile) : findRulesFile(cwd)
        if (!file) {
          return { ok: true, file: '', builtin: builtinRules.length, total: builtinRules.length }
        }
        try {
          const { rules } = loadRulesFile(file)
          ruleCache.set(file, { mtimeMs: statSync(file).mtimeMs, rules: mergeRules(builtinRules, rules) })
          lastRulesFile = file
          return {
            ok: true,
            file,
            builtin: builtinRules.length,
            total: builtinRules.length + rules.length,
          }
        } catch (error) {
          return {
            ok: false,
            file,
            builtin: builtinRules.length,
            total: builtinRules.length,
            error: error instanceof Error ? error.message : String(error),
          }
        }
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'write_guard_verify_chain',
      description:
        'Verify the internal hash links of one audit segment and return its head. Detects edited or deleted records in the middle; it cannot prove tail completeness without an externally protected head.',
      parameters: {
        type: 'object',
        properties: {
          file: { type: 'string', description: 'Audit file to verify; defaults to the configured path.' },
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: true,
          properties: {
            ok: { type: 'boolean' },
            records: { type: 'integer' },
            brokenAt: { type: 'integer' },
            reason: { type: 'string' },
            file: { type: 'string' },
          },
        },
        render: (value) => [
          {
            type: 'text',
            text: value.ok
              ? `write-guard: 审计链完整，${value.records} 条记录（${value.file}）`
              : `write-guard: 审计链断裂 @ 第 ${value.brokenAt} 条：${value.reason}`,
          },
        ],
      },
      timeoutMs: 10_000,
      isConcurrencySafe: () => true,
      async execute(args) {
        const file =
          typeof args?.file === 'string' && args.file
            ? args.file
            : config.auditFile || defaultAuditFile()
        return { ...verifyChain(file), file }
      },
    }),
  )

  // ---------------------------------------------------------------------
  // Settings panel route
  //
  // The client half registers a `settings.section` that reads and writes this
  // endpoint. Rides the same `webServer` the web app exposes; a profile without
  // one (Electron over file:// + IPC) simply has no panel and the switches stay
  // reachable through the `write_guard_config` tool.
  // ---------------------------------------------------------------------
  // Cordis throws on a service property that was not declared in `inject`, and
  // the desktop profile has no web server at all, so both paths stay guarded.
  let webServer
  try {
    webServer = typeof ctx.get === 'function' ? ctx.get('webServer') : undefined
    if (!webServer) webServer = ctx.webServer
  } catch {
    webServer = undefined
  }
  if (webServer && typeof webServer.register === 'function') {
    // Every failure mode must reject: resolving to '' would be parsed as an
    // empty patch and answered with 200, and `req.destroy()` alone can leave
    // the promise pending forever.
    const readBody = (req) =>
      new Promise((resolve, reject) => {
        const chunks = []
        let size = 0
        let settled = false
        const fail = (statusCode, message) => {
          if (settled) return
          settled = true
          reject(Object.assign(new Error(message), { statusCode }))
        }
        req.on('data', (chunk) => {
          if (settled) return
          size += chunk.length
          if (size > 64 * 1024) {
            fail(413, 'payload too large')
            return
          }
          chunks.push(chunk)
        })
        req.on('end', () => {
          if (settled) return
          settled = true
          resolve(Buffer.concat(chunks).toString('utf8'))
        })
        req.on('error', (error) => {
          if (settled) return
          settled = true
          reject(error)
        })
        req.on('close', () => {
          if (!req.readableEnded) fail(400, 'request aborted')
        })
      })
    const sendJson = (res, code, payload) => {
      res.statusCode = code
      res.setHeader('content-type', 'application/json; charset=utf-8')
      res.setHeader('cache-control', 'no-store')
      res.end(JSON.stringify(payload))
    }
    // Every custom route must pass the browser-trust fence, otherwise any open
    // page could rewrite the guard's switches. A missing or throwing fence is
    // a rejection, not a pass: this route writes security policy.
    const rejected = (req, res) => {
      let conn
      try {
        conn = typeof ctx.get === 'function' ? ctx.get('connection') : undefined
        if (!conn) conn = ctx.connection
      } catch {
        conn = undefined
      }
      if (!conn || typeof conn.requestRejection !== 'function') {
        sendJson(res, 503, { ok: false, error: 'trust fence unavailable' })
        return true
      }
      try {
        const code = conn.requestRejection(req)
        if (code === undefined || code === null || code === false) return false
        res.statusCode = typeof code === 'number' ? code : 403
        res.end()
        return true
      } catch (error) {
        ctx.logger?.warn?.(
          `write-guard: trust fence failed: ${error instanceof Error ? error.message : String(error)}`,
        )
        sendJson(res, 503, { ok: false, error: 'trust fence unavailable' })
        return true
      }
    }
    try {
      webServer.register({
        kind: 'exact',
        path: '/dsh-write-guard/config',
        handler: async (req, res) => {
          if (rejected(req, res)) return
          const method = (req.method || 'GET').toUpperCase()
          if (method === 'GET') {
            sendJson(res, 200, {
              ok: true,
              config: publicConfig(config),
              available: availableSwitches(),
              defaults: publicConfig(normalizeConfig({})),
              // The logical path only: the panel has no use for the host's
              // directory layout, and the browser should not learn it.
              file: join('<DSH_HOME>', 'write-guard', 'config.json'),
              restartOnly: [...RESTART_ONLY],
            })
            return
          }
          if (method !== 'POST') {
            sendJson(res, 405, { ok: false, error: 'method not allowed' })
            return
          }
          let payload
          try {
            const text = await readBody(req)
            payload = text ? JSON.parse(text) : {}
          } catch (error) {
            const code = error?.statusCode ?? 400
            sendJson(res, code, { ok: false, error: code === 413 ? 'payload too large' : 'invalid json' })
            return
          }
          try {
            const set = payload?.set && typeof payload.set === 'object' && !Array.isArray(payload.set) ? payload.set : {}
            const clear = Array.isArray(payload?.clear) ? payload.clear.map(String) : []
            const result = saveRuntimeConfig(set, clear)
            sendJson(res, 200, { ok: true, config: result.config, file: result.file, defaults: publicConfig(normalizeConfig({})) })
          } catch (error) {
            // A rejected patch carries its own 400; anything else is a real fault.
            const code = error?.statusCode ?? 500
            if (code >= 500) ctx.logger?.warn?.(`write-guard: config save failed: ${error instanceof Error ? error.message : String(error)}`)
            sendJson(res, code, {
              ok: false,
              error: code >= 500 ? 'failed to save config' : error instanceof Error ? error.message : String(error),
            })
          }
        },
      })
    } catch (error) {
      ctx.logger?.warn?.(`write-guard: settings route not registered: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  ctx.on('dispose', () => {
    // Returning the promise lets the host wait for the queued audit records
    // while a null audit still returns undefined.
    return audit?.close()
  })
}

function formatScan(value) {
  const lines = [
    `write-guard: ${value.decision.toUpperCase()} (风险分 ${value.score})`,
    value.reason ? `原因: ${value.reason}` : '',
    value.hits.length ? '命中:' : '命中: 无',
    ...value.hits.map((h) => `  - [${h.severity}] ${h.title} (${h.id})`),
    value.entropy?.length
      ? `高熵段: ${value.entropy.map((e) => `${e.length}字符/熵${e.entropy}`).join(', ')}`
      : '',
    value.truncated ? '注意: 内容被截断，仅扫描了前缀' : '',
  ]
  return lines.filter(Boolean).join('\n')
}

function formatStatus(value) {
  const s = value.stats
  const lines = [
    `write-guard mode=${value.mode} block>=${value.blockThreshold} ask>=${value.askThreshold}`,
    `扫描 ${s.scanned} | 放行 ${s.allowed} | 转人工 ${s.asked} | 拒绝 ${s.denied} | 隔离 ${s.quarantined}`,
    `shell 写入 ${s.shellWrites} | 写后校验 ${s.verified} | 哈希不符 ${s.tampered} | 二次扫描拦截 ${s.rescanBlocked}`,
    `规则: 内置 ${value.rules.builtin} | 文件 ${value.rules.file} | 自定义 ${value.rules.customLoaded}`,
    `自校验: ${value.integrity.status}${value.integrity.changed?.length ? ` (changed=${value.integrity.changed.join(',')})` : ''}`,
    value.auditFile ? `审计: ${value.auditFile}` : '审计: 关闭',
    value.quarantineDir ? `隔离区: ${value.quarantineDir}` : '隔离区: 关闭',
  ]
  if (value.recent.length) {
    lines.push('最近决策:')
    for (const item of value.recent.slice(0, 10)) {
      lines.push(`  ${item.at} ${item.decision} ${item.target} (${item.score}) ${item.hits.join(',')}`)
    }
  }
  return lines.join('\n')
}
