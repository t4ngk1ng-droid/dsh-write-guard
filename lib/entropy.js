/**
 * Shannon-entropy heuristic for opaque payloads.
 *
 * A long run of base64/hex characters with near-uniform symbol distribution
 * is either an encrypted blob, a compressed blob, or a random key. None of
 * those belong in a script an agent is about to write. Natural language and
 * source code sit well below the threshold, so the check is scoped to tokens
 * made only of ASCII encoding characters — CJK prose never enters the sample.
 */

const TOKEN_RE = /[A-Za-z0-9+/=_-]{40,}/g
const ENCODING_RE = /^[A-Za-z0-9+/=_-]+$/

/**
 * Shannon entropy in bits per symbol (base 2).
 * @param {string} text
 */
export function shannonEntropy(text) {
  if (text.length === 0) return 0
  const counts = new Map()
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    counts.set(ch, (counts.get(ch) ?? 0) + 1)
  }
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / text.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/**
 * Find long high-entropy encoding runs.
 * @param {string} text raw or normalized content
 * @param {{ threshold?: number, minLength?: number, maxRuns?: number, maxSample?: number }} config
 * @returns {{ length: number, entropy: number, sample: string }[]}
 */
export function scanEntropy(text, config = {}) {
  const threshold = config.threshold ?? 4.5
  const minLength = config.minLength ?? 200
  const maxRuns = config.maxRuns ?? 8
  const maxSample = config.maxSample ?? 4096
  const runs = []

  TOKEN_RE.lastIndex = 0
  let match
  while ((match = TOKEN_RE.exec(text)) !== null && runs.length < maxRuns) {
    const token = match[0]
    if (token.length < minLength || !ENCODING_RE.test(token)) continue
    // A repeated single character has zero entropy but can be very long;
    // cap the sample so a giant token does not dominate the hot path.
    const sample = token.length > maxSample ? token.slice(0, maxSample) : token
    const entropy = shannonEntropy(sample)
    // Hex has a theoretical maximum of 4 bits/symbol and can never reach the
    // base64-oriented default of 4.5. Give it a bounded, format-aware cutoff.
    const isHex = /^[0-9a-fA-F]+$/.test(sample)
    const effectiveThreshold = isHex ? Math.min(threshold, 3.5) : threshold
    if (entropy >= effectiveThreshold) {
      runs.push({
        length: token.length,
        entropy: Math.round(entropy * 100) / 100,
        sample: token.slice(0, 32),
      })
    }
  }
  return runs
}
