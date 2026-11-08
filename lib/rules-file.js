/**
 * Project-level custom rules: `write-guard.rules.json`.
 *
 * The file is discovered from the session cwd upward, capped in size and rule
 * count, and compiled with a small ReDoS screen. A malformed file fails the
 * load loudly but never takes the plugin down — the previous rule set stays
 * active, matching the "hot reload keeps the last good state" behavior a
 * security gate needs.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

export const RULES_FILE_NAME = 'write-guard.rules.json'
const MAX_FILE_BYTES = 256 * 1024
const MAX_RULES = 200
const MAX_PATTERN_LENGTH = 2000
const MAX_PATTERNS_PER_RULE = 64

/**
 * Native RegExp has no execution deadline. Keep project-supplied patterns in a
 * small safe subset: literal text, escaped atoms and single-character classes
 * such as \d, but no groups, alternation, lookaround, backreferences or
 * repetition. Every accepted pattern therefore advances in linear time.
 * Multiple pattern strings provide alternation without regex backtracking.
 */
function assertSafePattern(source, ruleId) {
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]
    if (ch === '\\') {
      const next = source[++i]
      if (next === undefined || /[1-9k]/.test(next)) {
        throw new Error(`rule ${ruleId}: backreferences are not allowed`)
      }
      continue
    }
    if ('.^$*+?()[]{}|'.includes(ch)) {
      throw new Error(
        `rule ${ruleId}: nested quantifier or other unsafe regex construct is not allowed; use literal patterns`,
      )
    }
  }
}

/** @param {string} startDir @returns {string|null} */
export function findRulesFile(startDir) {
  let dir = resolve(startDir || process.cwd())
  for (let depth = 0; depth < 64; depth++) {
    const candidate = join(dir, RULES_FILE_NAME)
    if (existsSync(candidate)) return candidate
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return null
}

function compilePattern(source, ruleId) {
  if (typeof source !== 'string') throw new Error(`rule ${ruleId}: pattern must be a string`)
  if (source.length > MAX_PATTERN_LENGTH) {
    throw new Error(`rule ${ruleId}: pattern exceeds ${MAX_PATTERN_LENGTH} characters`)
  }
  assertSafePattern(source, ruleId)
  try {
    return new RegExp(source, 'i')
  } catch (error) {
    throw new Error(`rule ${ruleId}: invalid regex (${error instanceof Error ? error.message : String(error)})`)
  }
}

function normalizeProbe(value, ruleId) {
  if (value === undefined) return undefined
  if (!Array.isArray(value)) throw new Error(`rule ${ruleId}: probe must be an array of strings`)
  return value.map((p) => {
    if (typeof p !== 'string') throw new Error(`rule ${ruleId}: probe entries must be strings`)
    return p.toLowerCase()
  })
}

function normalizePaths(value, ruleId) {
  if (value === undefined) return undefined
  if (!Array.isArray(value)) throw new Error(`rule ${ruleId}: paths must be an array of strings`)
  return value.map((p) => {
    if (typeof p !== 'string') throw new Error(`rule ${ruleId}: paths entries must be strings`)
    return p
  })
}

/**
 * @param {unknown} raw
 * @param {number} index
 */
function compileRule(raw, index) {
  if (raw === null || typeof raw !== 'object') throw new Error(`rules[${index}] must be an object`)
  const id = typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `custom-${index + 1}`
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id)) throw new Error(`rules[${index}]: invalid id`)
  const title = typeof raw.title === 'string' && raw.title.trim() ? raw.title.trim() : id
  const severity = Number(raw.severity)
  if (!Number.isFinite(severity) || severity < 1 || severity > 100) {
    throw new Error(`rule ${id}: severity must be a number between 1 and 100`)
  }
  if (!Array.isArray(raw.patterns) || raw.patterns.length === 0) {
    throw new Error(`rule ${id}: patterns must be a non-empty array`)
  }
  if (raw.patterns.length > MAX_PATTERNS_PER_RULE) {
    throw new Error(`rule ${id}: more than ${MAX_PATTERNS_PER_RULE} patterns`)
  }
  return {
    id,
    title,
    severity: Math.round(severity),
    category: typeof raw.category === 'string' ? raw.category : 'custom',
    probe: normalizeProbe(raw.probe, id),
    paths: normalizePaths(raw.paths, id),
    patterns: raw.patterns.map((p) => compilePattern(p, id)),
    source: 'custom',
  }
}

/**
 * Load and compile a rules file. Throws on a malformed file; the caller keeps
 * the previous rule set.
 * @param {string} file
 * @returns {{ rules: import('./patterns.js').Rule[], file: string }}
 */
export function loadRulesFile(file) {
  const stat = statSync(file)
  if (stat.size > MAX_FILE_BYTES) throw new Error(`rules file exceeds ${MAX_FILE_BYTES} bytes`)
  const parsed = JSON.parse(readFileSync(file, 'utf8'))
  if (parsed === null || typeof parsed !== 'object') throw new Error('rules file must contain an object')
  const list = parsed.rules ?? []
  if (!Array.isArray(list)) throw new Error('rules must be an array')
  if (list.length > MAX_RULES) throw new Error(`more than ${MAX_RULES} rules`)

  const seen = new Set()
  const rules = list.map((raw, index) => {
    const rule = compileRule(raw, index)
    if (seen.has(rule.id)) throw new Error(`duplicate rule id: ${rule.id}`)
    seen.add(rule.id)
    return rule
  })
  return { rules: rules.map((rule) => ({ ...rule, baseDir: dirname(file) })), file }
}

/**
 * Merge built-in rules with additive project rules. Project files are not
 * trusted to weaken the host's built-in detection policy.
 * @param {import('./patterns.js').Rule[]} builtins
 * @param {import('./patterns.js').Rule[]} custom
 */
export function mergeRules(builtins, custom = []) {
  if (custom.length === 0) return builtins
  const byId = new Map(builtins.map((r) => [r.id, r]))
  for (const rule of custom) {
    if (byId.has(rule.id)) throw new Error(`custom rule id collides with a built-in rule: ${rule.id}`)
    byId.set(rule.id, rule)
  }
  return [...byId.values()]
}
