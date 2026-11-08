/**
 * Minimal workspace-path glob matcher. Zero dependency: supports `**`, `*`,
 * `?`, and character classes, which is all the ignore-list needs. Paths are
 * normalized to forward slashes before matching so Windows and POSIX agree.
 */

const globCache = new Map()
const MAX_CACHE_ENTRIES = 256

/** @param {string} pattern @returns {RegExp} */
export function globToRegExp(pattern) {
  const key = String(pattern)
  const cached = globCache.get(key)
  if (cached) return cached

  let out = ''
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        // `**/` consumes any number of path segments; bare `**` crosses all.
        if (pattern[i + 2] === '/') {
          out += '(?:.*/)?'
          i += 2
        } else {
          out += '.*'
          i += 1
        }
      } else {
        out += '[^/]*'
      }
    } else if (ch === '?') {
      out += '[^/]'
    } else if (ch === '[') {
      const close = pattern.indexOf(']', i + 1)
      if (close === -1) {
        out += '\\['
      } else {
        const body = pattern.slice(i + 1, close)
        out += `[${body.startsWith('!') ? '^' + body.slice(1) : body}]`
        i = close
      }
    } else if ('\\^$.|+(){}'.includes(ch)) {
      out += '\\' + ch
    } else {
      out += ch
    }
  }
  const compiled = new RegExp(`^${out}$`, 'i')
  // Configuration normally contains a handful of stable patterns. Bound the
  // cache anyway so untrusted/dynamic configuration cannot grow it forever.
  if (globCache.size >= MAX_CACHE_ENTRIES) globCache.clear()
  globCache.set(key, compiled)
  return compiled
}

/** @param {string} p */
export function normalizePath(p) {
  return String(p ?? '').replace(/\\/g, '/')
}

/**
 * Whether `path` matches any glob in `patterns`. Both absolute and
 * workspace-relative paths are tested; a pattern without a leading slash can
 * match at any depth.
 * @param {string} path
 * @param {string[]} patterns
 */
export function matchesAny(path, patterns) {
  if (!patterns || patterns.length === 0) return false
  const normalized = normalizePath(path)
  const segments = normalized.split('/')
  for (const pattern of patterns) {
    if (globToRegExp(pattern).test(normalized)) return true
    if (!pattern.includes('/') && segments.some((seg) => globToRegExp(pattern).test(seg))) {
      return true
    }
  }
  return false
}
