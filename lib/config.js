/**
 * Configuration normalization. Every knob has a safe default; invalid values
 * fall back instead of failing the plugin at mount time. Rendering happens on
 * the pre-execute hot path, so this module does no I/O.
 */

export const DEFAULT_CONFIG = Object.freeze({
  // --- verdict thresholds -------------------------------------------------
  mode: 'enforce', // enforce | dry-run | off
  blockThreshold: 70,
  askThreshold: 40,

  // --- scan budget --------------------------------------------------------
  maxScanBytes: 512 * 1024,
  maxContentBytes: 32 * 1024 * 1024,
  maxVerifyBytes: 8 * 1024 * 1024,
  truncatePolicy: 'ask', // ask | allow

  // --- path policy --------------------------------------------------------
  scriptPolicy: 'ask', // ask | allow | deny
  docPolicy: 'downgrade', // downgrade | enforce
  blockBinaries: true,
  ignorePaths: [],

  // --- rules --------------------------------------------------------------
  allowRules: [],
  rulesFile: '',
  watchRules: true,

  // --- evidence -----------------------------------------------------------
  quarantine: true,
  quarantineDir: '',
  audit: true,
  auditFile: '',
  auditMaxBytes: 5 * 1024 * 1024,
  auditHashChain: true,

  // --- post-write verification -------------------------------------------
  verifyWrites: true,
  verifyPolicy: 'block', // block | audit

  // --- shell writes -------------------------------------------------------
  shellGuard: true,
  shellUnknownPolicy: 'ask', // ask | allow

  // --- content heuristics -------------------------------------------------
  entropy: true,
  entropyThreshold: 4.5,
  entropyMinLength: 200,
  homoglyph: true,

  // --- plugin self-integrity ---------------------------------------------
  integrity: true,

  // --- notifications ------------------------------------------------------
  notify: false,
  notifyCommand: '',
  notifyMinScore: 70,

  // --- failure policy -----------------------------------------------------
  onScannerError: 'ask', // ask | allow
})

function clamp(n, lo, hi, fallback) {
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : fallback
}

function pick(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback
}

function stringArray(value, fallback) {
  return Array.isArray(value) ? value.map(String) : fallback
}

/**
 * @param {Record<string, unknown>} input raw plugin config
 * @returns {typeof DEFAULT_CONFIG}
 */
export function normalizeConfig(input = {}) {
  const cfg = { ...DEFAULT_CONFIG, ...input }

  cfg.mode = pick(cfg.mode, ['enforce', 'dry-run', 'off'], DEFAULT_CONFIG.mode)
  cfg.blockThreshold = clamp(Number(cfg.blockThreshold), 1, 100, DEFAULT_CONFIG.blockThreshold)
  cfg.askThreshold = clamp(Number(cfg.askThreshold), 0, 100, DEFAULT_CONFIG.askThreshold)
  if (cfg.askThreshold > cfg.blockThreshold) cfg.askThreshold = cfg.blockThreshold

  cfg.maxScanBytes = Math.floor(clamp(Number(cfg.maxScanBytes), 1024, 16 * 1024 * 1024, DEFAULT_CONFIG.maxScanBytes))
  cfg.maxContentBytes = Math.floor(
    clamp(Number(cfg.maxContentBytes), 1024 * 1024, 512 * 1024 * 1024, DEFAULT_CONFIG.maxContentBytes),
  )
  cfg.maxVerifyBytes = Math.floor(
    clamp(Number(cfg.maxVerifyBytes), 1024, 64 * 1024 * 1024, DEFAULT_CONFIG.maxVerifyBytes),
  )
  cfg.truncatePolicy = pick(cfg.truncatePolicy, ['ask', 'allow'], DEFAULT_CONFIG.truncatePolicy)

  cfg.scriptPolicy = pick(cfg.scriptPolicy, ['ask', 'allow', 'deny'], DEFAULT_CONFIG.scriptPolicy)
  cfg.docPolicy = pick(cfg.docPolicy, ['downgrade', 'enforce'], DEFAULT_CONFIG.docPolicy)
  cfg.blockBinaries = cfg.blockBinaries !== false
  cfg.ignorePaths = stringArray(cfg.ignorePaths, DEFAULT_CONFIG.ignorePaths)

  cfg.allowRules = stringArray(cfg.allowRules, DEFAULT_CONFIG.allowRules)
  cfg.rulesFile = typeof cfg.rulesFile === 'string' ? cfg.rulesFile : ''
  cfg.watchRules = cfg.watchRules !== false

  cfg.quarantine = cfg.quarantine !== false
  cfg.quarantineDir = typeof cfg.quarantineDir === 'string' ? cfg.quarantineDir : ''
  cfg.audit = cfg.audit !== false
  cfg.auditFile = typeof cfg.auditFile === 'string' ? cfg.auditFile : ''
  cfg.auditMaxBytes = Math.floor(
    clamp(Number(cfg.auditMaxBytes), 64 * 1024, 1024 * 1024 * 1024, DEFAULT_CONFIG.auditMaxBytes),
  )
  cfg.auditHashChain = cfg.auditHashChain !== false

  cfg.verifyWrites = cfg.verifyWrites !== false
  cfg.verifyPolicy = pick(cfg.verifyPolicy, ['block', 'audit'], DEFAULT_CONFIG.verifyPolicy)

  cfg.shellGuard = cfg.shellGuard !== false
  cfg.shellUnknownPolicy = pick(cfg.shellUnknownPolicy, ['ask', 'allow'], DEFAULT_CONFIG.shellUnknownPolicy)

  cfg.entropy = cfg.entropy !== false
  cfg.entropyThreshold = clamp(Number(cfg.entropyThreshold), 3, 8, DEFAULT_CONFIG.entropyThreshold)
  cfg.entropyMinLength = Math.floor(
    clamp(Number(cfg.entropyMinLength), 40, 1024 * 1024, DEFAULT_CONFIG.entropyMinLength),
  )
  cfg.homoglyph = cfg.homoglyph !== false

  cfg.integrity = cfg.integrity !== false

  cfg.notify = cfg.notify === true
  cfg.notifyCommand = typeof cfg.notifyCommand === 'string' ? cfg.notifyCommand : ''
  cfg.notifyMinScore = clamp(Number(cfg.notifyMinScore), 0, 100, DEFAULT_CONFIG.notifyMinScore)

  cfg.onScannerError = pick(cfg.onScannerError, ['ask', 'allow'], DEFAULT_CONFIG.onScannerError)
  return cfg
}
