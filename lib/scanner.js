/**
 * Write scanner: decides whether one tool call may write what it is about to
 * write. Pure and synchronous — it runs on the `tools/pre-execute` hot path,
 * so it performs no I/O beyond the caller-supplied strings.
 */

import { createHash } from 'node:crypto'
import { TextDecoder } from 'node:util'
import { relative, resolve } from 'node:path'
import { DEFAULT_CONFIG, normalizeConfig } from './config.js'
import { scanEntropy } from './entropy.js'
import {
  ARCHIVE_EXTENSIONS,
  BINARY_EXTENSIONS,
  DOC_EXTENSIONS,
  DOUBLE_EXTENSION_RE,
  HOMOGLYPH_MAP,
  HOMOGLYPH_RE,
  LOW_RISK_EXTENSIONS,
  MAGIC_SIGNATURES,
  RULES,
  SCRIPT_EXTENSIONS,
  TEXT_LIKE_EXTENSIONS,
} from './patterns.js'
import { matchesAny, normalizePath } from './glob.js'

export { DEFAULT_CONFIG, normalizeConfig }

/** Tools that write file content, and how to pull (path, content) out of them. */
const WRITE_TOOLS = new Map([
  ['write', (args) => ({ path: args.file_path, content: args.content })],
  ['edit', (args) => ({ path: args.file_path, content: args.new_string })],
  [
    'str_replace_editor',
    (args) => {
      if (args.command === 'create') return { path: args.path, content: args.file_text }
      if (args.command === 'str_replace') return { path: args.path, content: args.new_str }
      if (args.command === 'insert') return { path: args.path, content: args.new_str }
      return null
    },
  ],
  // Not a real DSH tool today, but cheap insurance if a preset adds one.
  ['apply_patch', (args) => ({ path: inferPatchPath(args), content: JSON.stringify(args) })],
])

/** `apply_patch` has no fixed schema; best-effort a path out of the payload. */
function inferPatchPath(args) {
  for (const key of ['path', 'file_path', 'filePath']) {
    if (typeof args?.[key] === 'string') return args[key]
  }
  const m = /\*\*\* (?:Update|Add|Delete) File:\s*(.+)/.exec(args?.patch ?? '')
  return m ? m[1].trim() : '(patch)'
}

/**
 * Whether this call is a content write we can inspect.
 * @param {string} toolName
 * @param {unknown} args
 */
export function extractWrite(toolName, args) {
  const pick = WRITE_TOOLS.get(toolName)
  if (!pick || args === null || typeof args !== 'object') return null
  const picked = pick(args)
  if (!picked || typeof picked.path !== 'string') return null
  const content = typeof picked.content === 'string' ? picked.content : String(picked.content ?? '')
  return { path: picked.path, content }
}

/**
 * Extension of a path, lowercased, including the dot.
 * Win32 strips trailing dots and spaces from a filename, so `payload.exe. `
 * lands as `payload.exe`; the extension must be read the same way.
 */
export function extname(path) {
  const base = (normalizePath(path).split('/').pop() ?? '').replace(/[. ]+$/, '')
  const idx = base.lastIndexOf('.')
  return idx <= 0 ? '' : base.slice(idx).toLowerCase()
}

/** Heuristic binary test: any NUL is a strong signal, control bytes a weaker one. */
export function looksBinary(text, maxSample = 512 * 1024) {
  const sample = text.length > maxSample ? text.slice(0, maxSample) : text
  if (sample.length === 0) return false
  let bad = 0
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i)
    if (code === 0) return true
    if (code < 9 || (code > 13 && code < 32) || code === 127) bad++
  }
  return bad / sample.length > 0.02
}

const INVISIBLE_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g
/** Every character the folding steps can change is non-ASCII. */
const NON_ASCII_RE = /[^\x00-\x7f]/

/**
 * Fold the tricks that defeat keyword matching:
 *   - zero-width and bidi control characters (keyword splitting)
 *   - compatibility forms via NFKC (full-width Latin, ligatures)
 *   - confusable Cyrillic/Greek letters that render as Latin
 * @param {string} text
 */
export function normalizeText(text, homoglyph = true) {
  // Runs on every write. Pure ASCII cannot contain an invisible control
  // character, a compatibility form or a confusable, so skip three full
  // passes over the sample.
  if (!NON_ASCII_RE.test(text)) return text
  const stripped = text.replace(INVISIBLE_RE, '')
  let folded
  try {
    folded = stripped.normalize('NFKC')
  } catch {
    folded = stripped
  }
  return homoglyph ? folded.replace(HOMOGLYPH_RE, (ch) => HOMOGLYPH_MAP.get(ch) ?? ch) : folded
}

/**
 * Identify an executable/archive header in text content.
 * @param {string} content
 * @returns {{ id: string, label: string }|null}
 */
export function detectMagic(content) {
  if (content.length < 4) return null
  for (const sig of MAGIC_SIGNATURES) {
    if (sig.id === 'pe') continue
    // Magic numbers are bytes, not case-insensitive words: `pk` is not ZIP and
    // `elf` is not ELF.
    if (content.startsWith(sig.probe)) return { id: sig.id, label: sig.label }
  }
  // Two printable letters alone are not enough evidence for PE. Require the
  // exact-case MZ plus a control byte in the DOS header area. Printable
  // Latin-1 characters such as é are ordinary text, not binary evidence.
  if (content.startsWith('MZ') && /[\x00-\x08\x0b\x0c\x0e-\x1f\x80-\x9f]/.test(content.slice(2, 64))) {
    return { id: 'pe', label: 'PE/Windows 可执行文件' }
  }
  return null
}

/**
 * Return a valid UTF-8 prefix no larger than maxBytes, plus the full byte size.
 * Character count is not byte count: a 512 KB budget means 512 KB of UTF-8,
 * and the cut must not manufacture a replacement character.
 * @param {string} text
 * @param {number} maxBytes
 * @param {number} [knownBytes] previously computed UTF-8 byte length
 */
export function createSample(text, maxBytes, knownBytes) {
  const bytes = knownBytes ?? Buffer.byteLength(text, 'utf8')
  if (bytes <= maxBytes) return { sample: text, truncated: false, bytes }
  const prefix = text.length > maxBytes ? text.slice(0, maxBytes) : text
  const buffer = Buffer.from(prefix, 'utf8')
  const sample = new TextDecoder().decode(buffer.subarray(0, maxBytes), { stream: true })
  return { sample, truncated: true, bytes }
}

/**
 * Scan text against the rule set. Rules with a `probe` are skipped unless one
 * of their substrings appears, which keeps the hot path cheap on large files.
 * Both the raw text and its normalized variant are tested.
 * @param {string} text
 * @param {{ allowRules?: string[], maxScanBytes?: number, entropy?: boolean, entropyThreshold?: number, entropyMinLength?: number }} config
 * @param {import('./patterns.js').Rule[]} [rules]
 * @param {number} [knownBytes] previously computed UTF-8 byte length
 * @returns {{ hits: {id:string,category:string,severity:number,title:string}[], truncated: boolean, normalized: boolean, entropy: {length:number,entropy:number,sample:string}[] }}
 */
export function scanText(text, config = {}, rules = RULES, knownBytes) {
  const allow = config.allowRules?.length ? new Set(config.allowRules) : null
  const max = config.maxScanBytes ?? DEFAULT_CONFIG.maxScanBytes
  const { sample, truncated, bytes } = createSample(text, max, knownBytes)

  const normalizedSample = normalizeText(sample, config.homoglyph !== false)
  const variants = normalizedSample === sample ? [sample] : [sample, normalizedSample]
  const lowered = variants.map((v) => v.toLowerCase())
  const hits = []

  for (const rule of rules) {
    if (allow?.has(rule.id)) continue
    if (rule.probe && !rule.probe.some((p) => lowered.some((v) => v.includes(p)))) continue

    if (rule.id === 'obfuscation-long-line') {
      if (hasLongScriptLine(variants)) {
        hits.push({ id: rule.id, category: rule.category, severity: rule.severity, title: rule.title })
      }
      continue
    }

    if (rule.patterns.some((re) => variants.some((v) => re.test(v)))) {
      hits.push({ id: rule.id, category: rule.category, severity: rule.severity, title: rule.title })
    }
  }

  let entropy = []
  if (config.entropy !== false && !allow?.has('high-entropy-blob')) {
    entropy = scanEntropy(sample, {
      threshold: config.entropyThreshold,
      minLength: config.entropyMinLength,
    })
    if (entropy.length > 0) {
      hits.push({
        id: 'high-entropy-blob',
        category: 'encoded-payload',
        severity: 65,
        title: `高熵编码串（${entropy.length} 段）`,
      })
    }
  }

  return { hits, truncated, normalized: variants.length > 1, entropy, bytes, sample }
}

/** @param {string[]} variants */
function hasLongScriptLine(variants) {
  for (const sample of variants) {
    let length = 0
    let scriptish = false
    for (let i = 0; i <= sample.length; i++) {
      const ch = sample[i]
      if (i === sample.length || ch === '\n' || ch === '\r') {
        if (length > 3000 && scriptish) return true
        length = 0
        scriptish = false
        continue
      }
      length++
      if (ch === ';' || ch === '{' || ch === '}' || ch === '$' || ch === '`') scriptish = true
    }
  }
  return false
}

/** Aggregate severity: strongest hit plus a small correlate bonus. */
export function scoreHits(hits) {
  if (hits.length === 0) return 0
  const max = Math.max(...hits.map((h) => h.severity))
  const bonus = Math.min(15, (hits.length - 1) * 5)
  return Math.min(100, max + bonus)
}

/** Custom rules with a `paths` list only apply to matching targets. */
function rulesForPath(rules, path, cwd) {
  const absolute = resolve(cwd || process.cwd(), path)
  return rules.filter((rule) => {
    if (!rule.paths || rule.paths.length === 0) return true
    // Project rules are rooted at the rules file, not at whichever nested cwd
    // the agent happened to use. This also normalizes ./, .. and absolute paths.
    const root = rule.baseDir || cwd || process.cwd()
    const relativePath = normalizePath(relative(root, absolute))
    return matchesAny(relativePath, rule.paths)
  })
}

/**
 * Decide one write call.
 * @param {{ name: string, args: unknown, cwd?: string }} call
 * @param {ReturnType<typeof normalizeConfig>} config
 * @param {import('./patterns.js').Rule[]} [rules]
 * @returns {null | {
 *   decision: 'allow'|'ask'|'deny',
 *   dryRun: boolean,
 *   score: number,
 *   reason: string,
 *   path: string,
 *   hits: {id:string,category:string,severity:number,title:string}[],
 *   bytes: number,
 *   truncated: boolean,
 *   binary: boolean,
 *   normalized: boolean,
 *   magic: {id:string,label:string}|null,
 *   entropy: {length:number,entropy:number,sample:string}[],
 *   sha256: string,
 *   content: string,
 * }}
 */
export function scanToolCall(call, config, rules = RULES) {
  if (config.mode === 'off') return null
  const extracted = extractWrite(call.name, call.args)
  if (!extracted) return null

  const { path, content } = extracted
  const normalized = normalizePath(path)
  if (matchesAny(normalized, config.ignorePaths)) return null

  // --- hard size ceiling ---------------------------------------------------
  // The limit is bytes, just like maxScanBytes/maxVerifyBytes. byteLength does
  // not allocate a second full Buffer and also catches short CJK strings whose
  // UTF-8 representation exceeds the configured ceiling.
  const bytes = Buffer.byteLength(content, 'utf8')
  const hardLimit = config.maxContentBytes ?? DEFAULT_CONFIG.maxContentBytes
  if (bytes > hardLimit) {
    return {
      decision: 'ask',
      dryRun: config.mode === 'dry-run',
      score: config.askThreshold,
      reason: `write-guard 拦截（ask，风险分 ${config.askThreshold}）：内容超过硬上限 ${hardLimit} 字节，未做完整扫描`,
      path: normalized,
      hits: [],
      bytes,
      truncated: true,
      binary: false,
      normalized: false,
      magic: null,
      entropy: [],
      sha256: '',
      content: '',
    }
  }

  // Win32 drops trailing dots and spaces from a filename; the extension and
  // double-extension checks must see the name the filesystem will create.
  const filesystemPath = normalized.replace(/[. ]+$/, '')
  const ext = extname(filesystemPath)
  const binary = looksBinary(content, config.maxScanBytes)
  const magic = detectMagic(content)
  const effectiveRules = rulesForPath(rules, normalized, call.cwd)
  const { hits, truncated, normalized: folded, entropy } = scanText(content, config, effectiveRules, bytes)
  const reasons = []

  let score = 0

  // --- path-level risk -----------------------------------------------------
  if (BINARY_EXTENSIONS.has(ext)) {
    if (config.blockBinaries) {
      score = 100
      reasons.push(`写入可执行文件类型 ${ext}`)
    } else {
      score = Math.max(score, config.askThreshold)
      reasons.push(`写入可执行文件类型 ${ext}`)
    }
  }

  if (DOUBLE_EXTENSION_RE.test(filesystemPath)) {
    score = 100
    reasons.push('双扩展名伪装（文档后缀 + 可执行后缀）')
  }

  if (SCRIPT_EXTENSIONS.has(ext)) {
    if (config.scriptPolicy === 'deny') {
      score = Math.max(score, 100)
      reasons.push(`写入脚本文件类型 ${ext}`)
    } else if (config.scriptPolicy === 'ask') {
      score = Math.max(score, config.askThreshold)
      reasons.push(`写入脚本文件类型 ${ext}`)
    }
  }

  if (binary) {
    score = Math.max(score, 95)
    reasons.push('内容含二进制控制字节')
  }

  // --- file magic ----------------------------------------------------------
  if (magic) {
    const executableMagic = magic.id === 'pe' || magic.id === 'elf' || magic.id === 'macho-be' || magic.id === 'macho-le'
    if (executableMagic) {
      score = 100
      reasons.push(`内容是${magic.label}（伪装成文本文件）`)
    } else if (TEXT_LIKE_EXTENSIONS.has(ext) && !ARCHIVE_EXTENSIONS.has(ext)) {
      score = Math.max(score, 60)
      reasons.push(`文本文件里出现${magic.label}文件头`)
    }
  }

  // --- content-level risk --------------------------------------------------
  const hitScore = scoreHits(hits)
  if (hitScore > score) score = hitScore
  for (const hit of hits.slice(0, 4)) reasons.push(`${hit.title} [${hit.id}]`)

  if (truncated && config.truncatePolicy === 'ask') {
    score = Math.max(score, config.askThreshold)
    reasons.push(`内容超过 ${config.maxScanBytes} 字节，仅扫描前缀`)
  }

  // --- verdict -------------------------------------------------------------
  let decision = 'allow'
  if (score >= config.blockThreshold) decision = 'deny'
  else if (score >= config.askThreshold) decision = 'ask'

  // A README that quotes a malicious command is evidence, not an attack: the
  // bytes are inert until someone copies them into a shell, and a human is
  // about to read them. Downgrade instead of denying, so documenting a threat
  // does not get blocked. Extension- and magic-level hazards keep their
  // verdict — those are not documentation.
  if (config.docPolicy === 'downgrade' && DOC_EXTENSIONS.has(ext) && decision === 'deny' && !binary) {
    const pathHazard = BINARY_EXTENSIONS.has(ext) || DOUBLE_EXTENSION_RE.test(filesystemPath)
    // A user-authored custom rule is an explicit decision for this project;
    // documentation context must not silently downgrade it.
    const customHit = hits.some((h) => {
      const rule = effectiveRules.find((r) => r.id === h.id)
      return rule?.source === 'custom' || rule?.category === 'custom'
    })
    if (!pathHazard && !magic && !customHit) {
      decision = 'ask'
      reasons.push('文档类文件，降级为人工确认')
    }
  }

  const reason =
    decision === 'allow'
      ? ''
      : `write-guard 拦截（${decision}，风险分 ${score}）：${reasons.join('；')}`

  return {
    decision,
    dryRun: config.mode === 'dry-run',
    score,
    reason,
    path: normalized,
    hits,
    bytes,
    truncated,
    binary,
    normalized: folded,
    magic,
    entropy,
    sha256: createHash('sha256').update(content, 'utf8').digest('hex'),
    content,
  }
}
