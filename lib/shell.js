/**
 * Static extraction of file writes from shell commands.
 *
 * This is deliberately not a shell parser. It recognizes the handful of
 * shapes that put attacker-controlled bytes on disk — heredocs, echo/printf
 * redirects, tee, PowerShell content cmdlets, .NET file APIs, and
 * download/extract commands that write a path without exposing the bytes —
 * and classifies the rest as "unknown write" so the caller can decide how
 * strict to be.
 *
 * Anything it cannot prove safe is surfaced as an unknown write rather than
 * silently ignored: the shell is the largest bypass surface for a write guard.
 * A target containing a variable, command substitution or glob is marked
 * `dynamic`: its bytes may still be scanned when known, but the final path
 * cannot be verified after the command runs.
 */

const WRITE_TOOLS = new Set(['bash', 'pwsh', 'powershell'])

/** Targets that are sinks, not files. `-` is stdout/stderr for curl/wget. */
const NULL_TARGETS = new Set(['/dev/null', 'nul', 'null', '$null', '&1', '&2', '1', '2', '-'])

/** Shell expansions and glob characters make a literal path unresolvable. */
const DYNAMIC_PATH_RE = /[$`~*?{}]|\(|\)|\[|\]|%[A-Za-z_][A-Za-z0-9_]*%/

/** @typedef {{ path: string, content: string, source: string, dynamic?: boolean }} ShellWrite */
/** @typedef {{ path: string, source: string, dynamic?: boolean }} UnknownWrite */

/**
 * @param {string} tool
 * @param {unknown} args
 * @returns {null | { command: string }}
 */
export function extractCommand(tool, args) {
  if (!WRITE_TOOLS.has(tool) || args === null || typeof args !== 'object') return null
  const command = args.command ?? args.script ?? args.cmd
  return typeof command === 'string' && command.length > 0 ? { command } : null
}

/** Strip a trailing quote pair and surrounding whitespace. */
function cleanTarget(value) {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/^["']|["']$/g, '')
}

function isSink(path) {
  return !path || NULL_TARGETS.has(path.toLowerCase())
}

/**
 * Whether the literal target still contains runtime expansion (a variable,
 * command substitution or glob). Such a write can be scanned for content, but
 * Node must not try to verify a path the shell never used literally.
 * MSYS/Git Bash absolute paths (`/tmp/x`, `/c/...`) are also not win32
 * root-relative paths, so they are excluded on Windows for the same reason.
 * @param {string} path
 */
function isDynamicPath(path) {
  if (DYNAMIC_PATH_RE.test(path)) return true
  if (process.platform === 'win32' && path.startsWith('/') && !path.startsWith('//')) return true
  return false
}

/** @param {{ path: string, dynamic?: boolean }} write */
function markDynamic(write) {
  return { ...write, dynamic: write.dynamic ?? isDynamicPath(write.path) }
}

/** Decode the subset of bash double-quote escapes that matters for content rules. */
function decodeDoubleQuoted(value) {
  return value
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\r/g, '\r')
    .replace(/\\(["'`$\\])/g, '$1')
}

/** Read the first shell token (quoted or bare) without consuming the rest. */
function firstShellToken(text) {
  const m = /^\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^\s;&|]+))/.exec(text)
  if (!m) return undefined
  if (m[1] !== undefined) return decodeDoubleQuoted(m[1])
  return m[2] ?? m[3]
}

/** First positional argument, skipping option tokens. */
function firstPositionalShellToken(text) {
  const tokens = text.match(/"(?:[^"\\]|\\.)*"|'(?:[^']*)'|[^\s]+/g) ?? []
  for (const token of tokens) {
    if (token.startsWith('-')) continue
    return cleanTarget(token)
  }
  return undefined
}

/**
 * Read the target of the redirect operator starting at `at` (a `>`).
 * @param {string} text
 * @param {number} at
 * @returns {{ path: string, end: number }|undefined}
 */
function readRedirectAt(text, at) {
  let i = at + 1 // past the first `>`
  if (text[i] === '>') i++ // past the append `>`
  if (text[i] === '|') i++ // bash `>|` noclobber override
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++
  const target = /^("([^"]+)"|'([^']+)'|([^\s;&|]+))/.exec(text.slice(i))
  if (!target) return undefined
  return { path: cleanTarget(target[2] ?? target[3] ?? target[4]), end: i + target[0].length }
}

/**
 * Find the first real `>`/`>>` in one statement and read its target. `>` inside
 * quotes is data, not a redirect; stopping at `;`/`|`/newline prevents a later
 * statement's redirect from being attributed to this command.
 * @param {string} text
 * @returns {{ before: string, path: string }|undefined}
 */
function findRedirect(text) {
  let quote = null
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (quote) {
      if (ch === '\\' && quote === '"') {
        i++
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '>' || ch === ';' || ch === '|' || ch === '\n') {
      if (ch !== '>') return undefined
      const parsed = readRedirectAt(text, i)
      if (!parsed) return undefined
      return { before: text.slice(0, i), path: parsed.path }
    }
  }
  return undefined
}

/**
 * Every redirect whose operator is outside quotes. This is what stops
 * `echo "x > y"` from becoming a write of `y`: the `>` there is data. Nested
 * interpreter commands are handled separately by extractNestedCommands.
 * @param {string} command
 * @returns {{ path: string, source: string }[]}
 */
function extractRedirectWrites(command) {
  const unknown = []
  let quote = null
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (quote) {
      if (ch === '\\' && quote === '"') {
        i++
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '>' && command[i - 1] !== '<' && command[i - 1] !== '&') {
      const parsed = readRedirectAt(command, i)
      if (parsed) {
        if (!isSink(parsed.path)) unknown.push({ path: parsed.path, source: 'redirect' })
        i = parsed.end - 1
      }
      continue
    }
    if (ch === '&' && command[i + 1] === '>') {
      const parsed = readRedirectAt(command, i + 1)
      if (parsed) {
        if (!isSink(parsed.path)) unknown.push({ path: parsed.path, source: 'redirect' })
        i = parsed.end - 1
      }
    }
  }
  return unknown
}

/**
 * Commands passed to another shell via `-c`/`-Command`/`/c` really execute, so
 * their quoted body is parsed again. Depth is bounded to keep a pathological
 * nesting from turning into unbounded recursion.
 * @param {string} command
 * @returns {string[]}
 */
function extractNestedCommands(command) {
  const out = []
  const re = /\b(?:bash|sh|zsh|dash|cmd|pwsh|powershell)(?:\.exe)?\s+(?:-[A-Za-z]*c[A-Za-z]*|\/c|--command)\s+(?:"([^"]*)"|'([^']*)')/gi
  let m
  while ((m = re.exec(command)) !== null) {
    const inner = m[1] ?? m[2] ?? ''
    if (inner) out.push(inner)
  }
  return out
}

// ---------------------------------------------------------------------------
// PowerShell token helpers
// ---------------------------------------------------------------------------

/**
 * Read one PowerShell token without consuming the rest of the statement.
 * Double-quoted strings expand `$var`/`$(...)`; `quoted` records that so a
 * caller can distinguish a literal from a runtime value.
 * @param {string} text
 */
function readPowerShellToken(text) {
  const m = /^\s*(?:"((?:[^"`]|`.)*)"|'([^']*)'|([^\s;|]+))/.exec(text)
  if (!m) return undefined
  if (m[1] !== undefined) {
    return {
      value: m[1].replace(/`(.)/g, '$1'),
      quoted: 'double',
      // Any `$` immediately followed by a non-space is a variable or
      // subexpression (`$x`, `$env:X`, `$($x)`, `$_`, `$1`, `$$`).
      expandable: /\$[^\s"']/.test(m[1]),
    }
  }
  if (m[2] !== undefined) return { value: m[2], quoted: 'single' }
  return { value: m[3], quoted: 'bare' }
}

/**
 * The literal value a token contributes, or undefined when PowerShell would
 * evaluate it at runtime (variable, subexpression, array or type literal).
 * @param {{ value: string, quoted: string, expandable?: boolean }|undefined} token
 * @returns {string|undefined}
 */
function literalValue(token) {
  if (!token) return undefined
  if (token.quoted === 'single') return token.value
  if (token.quoted === 'double') return token.expandable ? undefined : token.value
  // A bare word is a string in PowerShell unless it is a variable, command
  // substitution, array, hashtable, script block or type expression.
  if (/^[$(@{\[]/.test(token.value)) return undefined
  return token.value
}

/**
 * Split heredocs into three parts:
 *
 *   masked      — the command with every body replaced by a blank line, so
 *                 documentation or sample code is not mistaken for commands;
 *   shellBodies — bodies that a shell will execute (`bash <<EOF`,
 *                 `cat <<EOF | bash`), parsed recursively as commands;
 *   opaqueBodies— bodies for non-shell interpreters (`python <<EOF`), whose
 *                 bytes cannot be inspected, surfaced as an unknown write.
 *
 * The opening line and the closing delimiter stay in `masked`, which keeps
 * `cat <<EOF | tee file` visible.
 * @param {string} command
 */
function splitHeredocs(command) {
  const result = { masked: command, shellBodies: [], opaqueBodies: [] }
  if (!command.includes('<<')) return result
  const lines = command.split('\n')
  const masked = []
  let delimiter = null
  let opening = ''
  let body = []
  for (const line of lines) {
    if (delimiter !== null) {
      if (line.trim() === delimiter) {
        masked.push(line)
        if (isShellScriptHeredoc(opening)) result.shellBodies.push(body.join('\n'))
        else if (isOpaqueScriptHeredoc(opening)) result.opaqueBodies.push(body.join('\n'))
        delimiter = null
        body = []
        opening = ''
      } else {
        masked.push('')
        body.push(line)
      }
      continue
    }
    masked.push(line)
    const found = findHeredocDelimiter(line)
    if (found) {
      delimiter = found
      opening = line
    }
  }
  result.masked = masked.join('\n')
  return result
}

/** Commands whose heredoc body is another shell script. */
function isShellScriptHeredoc(opening) {
  if (/\|\s*(?:bash|sh|zsh|dash|pwsh|powershell|cmd)(?:\.exe)?\b/i.test(opening)) return true
  const head = interpreterHead(opening)
  return /^(?:bash|sh|zsh|dash|pwsh|powershell|cmd)(?:\.exe)?$/i.test(head)
}

/** Interpreters that execute the body but are not shell syntax. */
function isOpaqueScriptHeredoc(opening) {
  if (/\|\s*(?:python3?|perl|ruby|node|deno|bun)(?:\.exe)?\b/i.test(opening)) return true
  const head = interpreterHead(opening)
  return /^(?:python3?|perl|ruby|node|deno|bun)(?:\.exe)?$/i.test(head)
}

/** First real command token, skipping sudo/env-style prefixes. */
function interpreterHead(opening) {
  const tokens = opening.trim().split(/\s+/)
  let index = 0
  while (['sudo', 'env', 'nohup', 'command'].includes(tokens[index])) index++
  return tokens[index] ?? ''
}

/**
 * Delimiter of a heredoc opened on this line, ignoring `<<` inside quotes and
 * arithmetic shifts (`9 << 2`).
 * @param {string} line
 */
function findHeredocDelimiter(line) {
  let quote = null
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]
    if (quote) {
      if (ch === '\\' && quote === '"') {
        i++
        continue
      }
      if (ch === quote) quote = null
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch !== '<' || line[i + 1] !== '<') continue
    let j = i + 2
    if (line[j] === '-') j++
    while (line[j] === ' ' || line[j] === '\t') j++
    const quoteChar = line[j] === "'" || line[j] === '"' ? line[j] : ''
    if (quoteChar) j++
    const start = j
    while (j < line.length && /[A-Za-z0-9_]/.test(line[j])) j++
    if (j === start) continue
    const name = line.slice(start, j)
    if (quoteChar && line[j] !== quoteChar) continue
    return name
  }
  return null
}

/**
 * End index of the current PowerShell statement. Separators inside quotes are
 * part of the argument, not statement boundaries.
 * @param {string} text
 */
function statementEnd(text) {
  let quote = null
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (quote) {
      if (ch === '`' && quote === '"') {
        i++
        continue
      }
      if (ch === quote) {
        if (quote === "'" && text[i + 1] === "'") {
          i++
          continue
        }
        quote = null
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '\n' || ch === ';' || ch === '|') return i
  }
  return -1
}

/**
 * Read a `-Name value` or `-Name:value` parameter from one statement segment.
 * @param {string} segment
 * @param {string} name regex fragment, e.g. `Value` or `(?:Path|FilePath)`
 */
function readNamedPowerShell(segment, name) {
  const m = new RegExp(`-${name}\\b\\s*:?`, 'i').exec(segment)
  if (!m) return undefined
  return readPowerShellToken(segment.slice(m.index + m[0].length))
}

// ---------------------------------------------------------------------------
// PowerShell writers
// ---------------------------------------------------------------------------

/**
 * Set-Content / Add-Content / Out-File. Named parameters are read in any
 * order; a non-literal value (run-time expression) or a command without
 * `-Value` (pipeline input) becomes an unknown write instead of an empty
 * "known" one.
 * @param {string} command
 */
function extractPowerShellCmdlets(command) {
  const known = []
  const unknown = []
  const re = /\b(Set-Content|Add-Content|Out-File|Set-Item)\b/gi
  let m
  while ((m = re.exec(command)) !== null) {
    const after = command.slice(m.index + m[0].length)
    const end = statementEnd(after)
    const segment = end === -1 ? after : after.slice(0, end)
    const source = m[1].toLowerCase()

    const namedPath = readNamedPowerShell(segment, '(?:Path|FilePath|LiteralPath)')
    let path = namedPath?.value
    let valueToken = readNamedPowerShell(segment, 'Value')

    if (!path) {
      // Positional form: `Set-Content file "content"`. Only accept a first
      // token that is not an option; resolving option/value pairs generally is
      // not reliable, and guessing a wrong path is worse than an unknown write.
      const position = /^\s*(?:"([^"]+)"|'([^']+)'|([^\s;|]+))/.exec(segment)
      const candidate = position?.[1] ?? position?.[2] ?? position?.[3]
      if (!candidate || candidate.startsWith('-')) continue
      path = candidate
      if (valueToken === undefined) {
        valueToken = readPowerShellToken(segment.slice(position[0].length))
      }
    }
    if (!path || isSink(path)) continue

    // No -Value: Set-Content/Add-Content read the pipeline, Out-File writes
    // whatever flows in. Both are unknown bytes.
    if (valueToken === undefined) {
      unknown.push({ path, source })
      continue
    }
    const value = literalValue(valueToken)
    if (value !== undefined) known.push({ path, content: value, source })
    else unknown.push({ path, source })
  }
  return { known, unknown }
}

/**
 * .NET file APIs. Only `WriteAllText(path, <literal>)` exposes the bytes;
 * byte arrays, line arrays and variables are unknown. A call whose arguments
 * cannot be split is still surfaced as a dynamic unknown write instead of
 * being dropped: `.NET` is a full expression language and the path may be a
 * variable or a nested call.
 * @param {string} command
 */
function extractDotnetWrites(command) {
  const known = []
  const unknown = []
  const re = /\[(?:System\.)?IO\.File\]::(?:Write|Append)All(Text|Bytes|Lines)\(/gi
  let m
  while ((m = re.exec(command)) !== null) {
    const rest = command.slice(re.lastIndex)
    const pathMatch = /^\s*(?:"([^"]+)"|'([^']+)'|([^\s,)]+))\s*,\s*/.exec(rest)
    if (!pathMatch) {
      unknown.push({ path: '(dotnet-write)', source: 'dotnet-write', dynamic: true })
      continue
    }
    const path = pathMatch[1] ?? pathMatch[2] ?? pathMatch[3]
    if (!path || isSink(path)) continue
    const token = readPowerShellToken(rest.slice(pathMatch[0].length))
    const value = m[1].toLowerCase() === 'text' ? literalValue(token) : undefined
    if (value !== undefined) known.push({ path, content: value, source: 'dotnet-write' })
    else unknown.push({ path, source: 'dotnet-write' })
  }
  return { known, unknown }
}

/**
 * New-Item -ItemType File. Without -Value it creates an empty file (known and
 * harmless); a run-time value is unknown.
 * @param {string} command
 */
function extractNewItemWrites(command) {
  const known = []
  const unknown = []
  const re = /\bNew-Item\b/gi
  let m
  while ((m = re.exec(command)) !== null) {
    const after = command.slice(m.index + m[0].length)
    const end = statementEnd(after)
    const segment = end === -1 ? after : after.slice(0, end)
    if (!/-ItemType\s+(?:"File"|'File'|File)\b/i.test(segment)) continue
    const path = readNamedPowerShell(segment, '(?:Path|LiteralPath)')?.value
    if (!path || isSink(path)) continue
    const valueToken = readNamedPowerShell(segment, 'Value')
    if (valueToken === undefined) {
      known.push({ path, content: '', source: 'new-item' })
      continue
    }
    const value = literalValue(valueToken)
    if (value !== undefined) known.push({ path, content: value, source: 'new-item' })
    else unknown.push({ path, source: 'new-item' })
  }
  return { known, unknown }
}

// ---------------------------------------------------------------------------
// Known content
// ---------------------------------------------------------------------------

/**
 * Extract writes with known content (heredoc, echo/printf, content cmdlets).
 * @param {string} command
 * @param {string} [masked] command with heredoc bodies blanked
 * @returns {{ known: ShellWrite[], unknown: UnknownWrite[] }}
 */
function extractKnownWrites(command, masked = splitHeredocs(command).masked) {
  const known = []
  const unknown = []

  // --- bash heredoc: cat > file <<'EOF' ... EOF -------------------------
  const heredocRe = /cat\s*(>>?)\s*("([^"]+)"|'([^']+)'|([^\s;&|]+))\s*<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\6\s*\r?\n([\s\S]*?)\r?\n\7(?=\s|$)/g
  let m
  while ((m = heredocRe.exec(command)) !== null) {
    const path = cleanTarget(m[3] ?? m[4] ?? m[5])
    if (isSink(path)) continue
    known.push({ path, content: m[8], source: 'heredoc' })
  }

  // --- bash heredoc with the redirect first: cat <<'EOF' > file ----------
  // The common form in documentation and generated scripts; the regex above
  // only recognizes the `cat > file <<EOF` order.
  const heredocReverseRe = /cat\s*<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1\s*(>>?)\s*(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))\s*\r?\n([\s\S]*?)\r?\n\2(?=\s|$)/g
  while ((m = heredocReverseRe.exec(command)) !== null) {
    const path = cleanTarget(m[4] ?? m[5] ?? m[6])
    if (isSink(path)) continue
    known.push({ path, content: m[7], source: 'heredoc' })
  }

  // Everything except the heredoc body itself is parsed as a command. A
  // README heredoc that quotes `Set-Content ...` must not become a write.

  // --- echo into a redirect ---------------------------------------------
  // The bare-token branch must not start with a quote: otherwise the engine
  // backtracks out of `echo "x > y"` and reads `y` as a redirect target.
  const echoRe = /\becho\s+(?:-e\s+)?(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([^\s;&|>"']+))\s*>>?\s*(?:"([^"]+)"|'([^']+)'|([^\s;&|]+))/g
  while ((m = echoRe.exec(masked)) !== null) {
    const path = cleanTarget(m[4] ?? m[5] ?? m[6])
    if (isSink(path)) continue
    const raw = m[1] !== undefined ? decodeDoubleQuoted(m[1]) : (m[2] ?? m[3] ?? '')
    known.push({ path, content: raw, source: 'echo' })
  }

  // --- printf into a redirect -------------------------------------------
  // `printf '%s' "$payload"` writes its later arguments, not the format
  // string. Scan the format only when it has no conversion; otherwise the
  // bytes come from arguments the regex cannot see.
  const printfRe = /\bprintf\b/g
  while ((m = printfRe.exec(masked)) !== null) {
    const redirect = findRedirect(masked.slice(m.index + m[0].length))
    if (!redirect || isSink(redirect.path)) continue
    const format = firstShellToken(redirect.before)
    if (format === undefined || format.includes('%')) unknown.push({ path: redirect.path, source: 'printf' })
    else known.push({ path: redirect.path, content: format, source: 'printf' })
  }

  for (const part of [
    extractPowerShellCmdlets(masked),
    extractDotnetWrites(masked),
    extractNewItemWrites(masked),
  ]) {
    known.push(...part.known)
    unknown.push(...part.unknown)
  }

  return { known, unknown }
}

// ---------------------------------------------------------------------------
// Unknown content
// ---------------------------------------------------------------------------

/**
 * Archive extraction. Exports the destination directory, or the current
 * directory when the command relies on the tool's default.
 * @param {string} command
 * @returns {UnknownWrite[]}
 */
function extractArchiveWrites(command) {
  const unknown = []
  let m

  const expandRe = /\bExpand-Archive\b([^\n;|]*)/gi
  while ((m = expandRe.exec(command)) !== null) {
    const destination = readNamedPowerShell(m[1], 'DestinationPath')?.value
    unknown.push({ path: destination || '.', source: 'extract' })
  }

  const tarRe = /\btar\b([^\n;|]*)/gi
  while ((m = tarRe.exec(command)) !== null) {
    const args = m[1]
    // `tar -tzf` lists; only extraction writes files.
    if (!/(?:^|\s)(?:-[A-Za-z]*x[A-Za-z]*|--extract)(?=\s|$)/.test(args)) continue
    const destination = readNamedPowerShell(args, 'C')?.value ?? readNamedPowerShell(args, 'directory')?.value
    unknown.push({ path: destination || '.', source: 'extract' })
  }

  const unzipRe = /\bunzip\b([^\n;|]*)/gi
  while ((m = unzipRe.exec(command)) !== null) {
    const args = m[1]
    if (/(?:^|\s)-(?:l|t|p|v|Z)\b/.test(args)) continue
    const destination = readNamedPowerShell(args, 'd')?.value
    unknown.push({ path: destination || '.', source: 'extract' })
  }

  const sevenRe = /\b7z\b([^\n;|]*)/gi
  while ((m = sevenRe.exec(command)) !== null) {
    const args = m[1]
    if (!/(?:^|\s)(?:x|e)(?=\s|$)/.test(args)) continue
    // 7z accepts `-o<dir>` without a space.
    const destination = /(?:^|\s)-o\s*("([^"]+)"|'([^']+)'|([^\s;|]+))/.exec(args)
    const path = destination ? cleanTarget(destination[2] ?? destination[3] ?? destination[4]) : ''
    unknown.push({ path: path || '.', source: 'extract' })
  }

  return unknown
}

/**
 * `tee` writes its stdin to one or more files. The bytes are pipeline output,
 * which this parser does not model, so every target is an unknown write.
 * @param {string} command
 * @returns {UnknownWrite[]}
 */
function extractTeeWrites(command) {
  const unknown = []
  // `\b` would also match the `Tee` in `Tee-Object`; require a real token end.
  const re = /(?:^|[|])\s*tee(?:\.exe)?(?=\s|;|&|\||$)([^\n;|]*)/gi
  let m
  while ((m = re.exec(command)) !== null) {
    const tokens = m[1].match(/"(?:[^"\\]|\\.)*"|'(?:[^']*)'|[^\s]+/g) ?? []
    let optionsEnded = false
    for (const token of tokens) {
      if (!optionsEnded && token.startsWith('-')) {
        if (token === '--') optionsEnded = true
        continue
      }
      const path = cleanTarget(token)
      if (!path || isSink(path)) continue
      unknown.push({ path, source: 'tee' })
    }
  }

  // PowerShell's Tee-Object writes the same pipeline bytes. `-Variable` keeps
  // the value in memory and must not be mistaken for a file target.
  const psTeeRe = /\bTee-Object\b([^\n;|]*)/gi
  while ((m = psTeeRe.exec(command)) !== null) {
    const named = readNamedPowerShell(m[1], '(?:FilePath|Path)')?.value
    let path = named
    if (!path) {
      if (/-Variable\b/i.test(m[1])) continue
      path = firstPositionalShellToken(m[1])
    }
    if (!path || isSink(path)) continue
    unknown.push({ path, source: 'tee' })
  }

  return unknown
}

/**
 * Extract writes whose bytes come from the network, an archive or a pipe.
 * @param {string} command
 * @returns {UnknownWrite[]}
 */
function extractUnknownWrites(command) {
  const unknown = []

  // Download-to-file: curl -o, wget -O, Invoke-WebRequest -OutFile
  const downloadRe = /\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer)\b[^\n;|]*?(?:--output-document|--output|-OutFile|-Destination|-O|-o)(?![A-Za-z])\s*(?:"([^"]+)"|'([^']+)'|([^\s;|]+))/gi
  let m
  while ((m = downloadRe.exec(command)) !== null) {
    let path = cleanTarget(m[1] ?? m[2] ?? m[3])
    // `--output=file` and PowerShell's `-OutFile:file` attach the value with
    // a separator instead of a space.
    if (path.startsWith('=') || path.startsWith(':')) path = path.slice(1)
    if (isSink(path)) continue
    // `curl -O URL` names the local file after the remote one: the captured
    // token is a URL, not a path Node can verify.
    const remote = /^[a-z][a-z0-9+.-]*:\/\//i.test(path)
    unknown.push(remote ? { path, source: 'download', dynamic: true } : { path, source: 'download' })
  }

  // Classic LOLBin downloads write a file whose name this parser cannot split
  // reliably (the file is the last positional argument). Surface the command
  // as one dynamic unknown write instead of dropping it.
  if (/\bcertutil(?:\.exe)?\b[^\n;|]*(?:-urlcache|-decode\b|-decodehex\b|-f\b)/i.test(command)) {
    unknown.push({ path: '(certutil-write)', source: 'download', dynamic: true })
  }
  if (/\bbitsadmin(?:\.exe)?\s+\/transfer\b/i.test(command)) {
    unknown.push({ path: '(bitsadmin-write)', source: 'download', dynamic: true })
  }

  // Start-Process can redirect a child's stdout/stderr to a file. Match the
  // parameter itself so both streams in one call are captured.
  const redirectStdRe = /-RedirectStandard(?:Output|Error)\s+(?:"([^"]+)"|'([^']+)'|([^\s;|]+))/gi
  while ((m = redirectStdRe.exec(command)) !== null) {
    const path = cleanTarget(m[1] ?? m[2] ?? m[3])
    if (isSink(path)) continue
    unknown.push({ path, source: 'redirect' })
  }

  unknown.push(...extractArchiveWrites(command))
  unknown.push(...extractTeeWrites(command))
  unknown.push(...extractRedirectWrites(command))

  return unknown
}

/**
 * Parse one command level, then recursively parse commands passed to another
 * shell (`bash -c "..."`, `powershell -Command "..."`).
 * @param {string} command
 * @param {number} [depth]
 * @returns {{ known: ShellWrite[], unknown: UnknownWrite[] }}
 */
function extractFromCommand(command, depth = 0) {
  const heredocs = splitHeredocs(command)
  const { known, unknown: inlineUnknown } = extractKnownWrites(command, heredocs.masked)
  // Inline unknowns come first so a content writer (printf, Set-Content, ...)
  // wins over the generic redirect that carries the same target.
  const unknown = [...inlineUnknown, ...extractUnknownWrites(heredocs.masked)]
  if (heredocs.opaqueBodies.length > 0) {
    // A non-shell interpreter executes bytes this parser cannot inspect.
    unknown.push({ path: '(stdin-script)', source: 'stdin-script', dynamic: true })
  }
  if (depth < 2) {
    for (const body of heredocs.shellBodies) {
      const sub = extractFromCommand(body, depth + 1)
      known.push(...sub.known)
      unknown.push(...sub.unknown)
    }
    for (const inner of extractNestedCommands(heredocs.masked)) {
      const sub = extractFromCommand(inner, depth + 1)
      known.push(...sub.known)
      unknown.push(...sub.unknown)
    }
  }
  return { known, unknown }
}

/**
 * @param {string} tool
 * @param {unknown} args
 * @returns {null | { known: ShellWrite[], unknown: UnknownWrite[] }}
 */
export function extractShellWrites(tool, args) {
  const extracted = extractCommand(tool, args)
  if (!extracted) return null
  const { known, unknown: nestedUnknown } = extractFromCommand(extracted.command)
  const knownPaths = new Set(known.map((w) => w.path))
  const seen = new Set()
  const unknown = []
  for (const write of nestedUnknown) {
    if (knownPaths.has(write.path)) continue
    if (seen.has(write.path)) continue
    seen.add(write.path)
    unknown.push(markDynamic(write))
  }
  const markedKnown = []
  const seenKnown = new Set()
  for (const write of known) {
    if (seenKnown.has(write.path)) continue
    seenKnown.add(write.path)
    markedKnown.push(markDynamic(write))
  }
  if (markedKnown.length === 0 && unknown.length === 0) return null
  return { known: markedKnown, unknown }
}
