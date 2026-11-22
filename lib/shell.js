import { createShellFlow } from './shell-flow.js'
import { lexShell } from './shell-lex.js'

const WRITE_TOOLS = new Set(['bash', 'pwsh', 'powershell'])
const SHELLS = /^(?:bash|sh|zsh|dash|cmd|pwsh|powershell)$/i
const INTERPRETERS = /^(?:python3?|perl|ruby|node|deno|bun)$/i
const DYNAMIC_PATH_RE = /[$`~*?{}()[\]]|%[A-Za-z_][A-Za-z0-9_]*%/

export function extractCommand(tool, args) {
  if (!WRITE_TOOLS.has(tool) || !args || typeof args !== 'object') return null
  const command = args.command ?? args.script ?? args.cmd
  return typeof command === 'string' && command ? { command } : null
}

function unquote(raw) {
  if (!raw) return ''
  return raw.length > 1 && (raw[0] === '"' || raw[0] === "'") && raw.at(-1) === raw[0] ? raw.slice(1, -1) : raw
}

function isSink(path, ps) {
  return !path || path === '/dev/null' || (process.platform === 'win32' && /^nul$/i.test(path)) || (ps && /^\$null$/i.test(path))
}

function literal(raw, ps) {
  if (raw === undefined) return undefined
  if (raw.startsWith("'")) return ps ? unquote(raw).replace(/''/g, "'") : unquote(raw)
  if (raw.includes('$') || (ps ? /^[(\[{@]/.test(raw) : raw.includes('`'))) return undefined
  const text = unquote(raw)
  return ps ? text.replace(/`(.)/g, '$1') : text.replace(/\\(["'$`\\])/g, '$1')
}

// Named PS parameters bind whole tokens. A string containing '-Path' or
// '-WhatIf' is data; a colon can attach a quoted value containing spaces.
function psArgs(args) {
  const named = new Map(), positional = []
  const switches = /^(?:whatif|confirm|nonewline|force|append|noclobber|passthru|verbose|debug|asbytestream)$/
  let uncertain = false
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--' || args[i] === '--%') { positional.push(...args.slice(i + 1)); break }
    const m = /^-([\w]+)(?::([\s\S]*))?$/.exec(args[i])
    if (!m) { positional.push(args[i]); continue }
    const key = m[1].toLowerCase()
    if (named.has(key)) uncertain = true
    if (switches.test(key)) named.set(key, m[2] ?? true)
    else if (m[2] !== undefined) named.set(key, m[2] || args[++i])
    else if (i + 1 < args.length && !/^-[A-Za-z]/.test(args[i + 1])) named.set(key, args[++i])
    else { named.set(key, undefined); uncertain = true }
  }
  const flag = named.get('whatif')
  return { named, positional, preview: !uncertain && (flag === true || /^\$true$/i.test(flag)) }
}

function option(args, names) {
  for (let i = 0; i < args.length; i++) {
    for (const key of names) {
      const raw = args[i]
      if (raw === key) return unquote(args[i + 1])
      if (raw.startsWith(key + '=')) return unquote(raw.slice(key.length + 1))
      if (key.length === 2 && raw.startsWith(key) && raw.length > 2) return unquote(raw.slice(2))
    }
  }
  return ''
}

// Only words in command position select a writer. Keep the command's actual
// arguments intact for content scanning; redirect targets are separate tokens.
function commandWords(segment, ps) {
  const words = segment.words.map(w => w.raw)
  let i = 0
  if (ps) {
    // Scope and control-flow prefixes still put the following token in command
    // position. A bare word in a normal command's argument list does not.
    if (/^(?:if|elseif|else|foreach|for|while|switch|try|catch|finally|do|function)$/i.test(words[0])) {
      const start = words.indexOf('{')
      if (start >= 0) i = start + 1
    }
    if (words[i] === '{') i++
    if (/^\$[\w:]+=$/.test(words[i])) i++
    else if (/^\$[\w:]+$/.test(words[i]) && words[i + 1] === '=') i += 2
    if (words[i] === '&') i++
  }
  if (!ps) {
    while (i < words.length && /^(?:[A-Za-z_]\w*=[\s\S]*|sudo|env|nohup|command|builtin|then|else|do|if|while|until|!|\{)$/.test(words[i])) i++
  }
  const raw = words[i] ?? ''
  const callable = !ps || i > 0 || !/^['"]/.test(raw)
  const name = callable ? unquote(raw).split(/[\\/]/).pop().replace(/\.exe$/i, '').toLowerCase() : ''
  return { name, args: words.slice(i + 1) }
}

function parseLevel(command, tool, cwd, inherited, depth, out) {
  const ps = /^(?:pwsh|powershell)$/i.test(tool)
  const flow = createShellFlow(tool, cwd)
  let pipedDocs = []
  for (const segment of lexShell(command, ps)) {
    const { name, args } = commandWords(segment, ps)
    const context = flow(segment.text, segment.previous, segment.next)
    const baseDir = context.baseDir ?? inherited.baseDir
    const cwdUnknown = context.cwdUnknown || inherited.cwdUnknown
    const skipVerify = context.skipVerify || inherited.skipVerify
    const seen = new Set()
    function add(path, source, content, dynamic = false) {
      if (isSink(path, ps)) return
      seen.add(path)
      const write = { path, source, dynamic: !!(dynamic || cwdUnknown || DYNAMIC_PATH_RE.test(path) || (process.platform === 'win32' && path.startsWith('/') && !path.startsWith('//'))) }
      if (baseDir) write.baseDir = baseDir
      if (skipVerify) write.skipVerify = true
      if (content === undefined) out.unknown.push(write)
      else out.known.push({ ...write, content })
    }
    const redirects = segment.redirects.map(r => unquote(r.word))
    const first = redirects[0]
    const commandTarget = segment.redirects.length === 1 && !segment.words.some(w => w.at > segment.redirects[0].at) ? first : undefined
    const docs = segment.documents
    if (name === 'cat' && first && docs[0]?.body !== undefined) add(first, 'heredoc', docs[0].body)
    if (name === 'echo' && commandTarget) {
      const values = args[0] === '-e' ? args.slice(1) : args
      if (values.length === 1 && !segment.text.includes('>|')) {
        let text = literal(values[0], ps)
        if (text !== undefined && args[0] === '-e') text = text.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r')
        if (text !== undefined) add(first, 'echo', text)
        else add(first, 'echo')
      }
    } else if (name === 'printf' && commandTarget) {
      const format = literal(args[0], ps)
      add(first, 'printf', format !== undefined && !format.includes('%') ? format : undefined)
    }

    if (ps && /^(?:set-content|add-content|set-item|out-file|new-item|tee-object|expand-archive|start-process|invoke-webrequest|iwr|invoke-restmethod|irm|start-bitstransfer)$/.test(name)) {
      const { named, positional, preview } = psArgs(args)
      const target = named.get('literalpath') ?? named.get('path') ?? named.get('filepath') ?? positional[0]
      const path = unquote(target)
      if (!preview) {
        if (/^(?:set-content|add-content|set-item|out-file|new-item)$/.test(name)) {
          const provider = name !== 'out-file' && /^env:/i.test(literal(target, true) ?? '')
          // `New-Item` defaults to a File when -ItemType is omitted, so only an
          // explicit non-file type (Directory, SymbolicLink, ...) is skipped.
          const rawItemType = named.get('itemtype') ?? named.get('type')
          const createsFile = name !== 'new-item' || rawItemType === undefined || /^file$/i.test(unquote(rawItemType))
          if (!provider && createsFile) {
            const hasNamedPath = ['path', 'literalpath', 'filepath'].some(key => named.has(key))
            const value = named.get('value') ?? positional[hasNamedPath ? 0 : 1]
            add(path, name, name === 'out-file' ? undefined : value === undefined && name === 'new-item' ? '' : literal(value, true))
          }
        } else if (name === 'expand-archive') add(unquote(named.get('destinationpath')) || '.', 'extract')
        else if (name === 'tee-object') {
          if (!named.has('variable') || named.has('filepath')) add(path, 'tee')
        } else if (name === 'start-process') {
          for (const key of ['redirectstandardoutput', 'redirectstandarderror']) add(unquote(named.get(key)), 'redirect')
        } else add(unquote(named.get('outfile') ?? named.get('destination')), 'download')
      }
    }
    // Static .NET method expressions also occur after a PS assignment. Match
    // the expression token, never a quoted string containing its spelling.
    if (ps) for (const word of segment.words) {
      const match = /^(?:\$\w+=)?\[(?:System\.)?IO\.File\]::(?:Write|Append)All(Text|Bytes|Lines)\(/i.exec(word.raw)
      if (!match) continue
      const expr = command.slice(word.at + match[0].length)
      const pair = /^\s*(?:"([^"]+)"|'([^']+)'|([^\s,()]+))\s*,\s*/.exec(expr)
      if (!pair) { add('(dotnet-write)', 'dotnet-write', undefined, true); continue }
      const value = /^\s*("(?:[^"`]|`.)*"|'(?:[^']|'')*')\s*\)/.exec(expr.slice(pair[0].length))
      add(pair[1] ?? pair[2] ?? pair[3], 'dotnet-write', match[1].toLowerCase() === 'text' && value ? literal(value[1], true) : undefined)
    }
    if (name === 'tee') {
      let options = true
      for (const arg of args) {
        if (options && arg.startsWith('-')) { if (arg === '--') options = false; continue }
        add(unquote(arg), 'tee')
      }
    } else if (name === 'curl' || name === 'wget') {
      const remoteName = name === 'curl' && args.includes('-O')
      const target = option(args, name === 'curl' ? ['--output', '-o', '-O'] : ['--output-document', '-O'])
      if (target !== '-') add(target || (remoteName ? '(remote-name)' : ''), 'download', undefined, remoteName || /^[\w+.-]+:\/\//.test(target))
    } else if (name === 'certutil' && args.some(a => /^-(?:urlcache|decode|decodehex|f)$/i.test(a))) add('(certutil-write)', 'download', undefined, true)
    else if (name === 'bitsadmin' && args.some(a => /^\/transfer$/i.test(a))) add('(bitsadmin-write)', 'download', undefined, true)
    else if (name === 'tar' && args.some(a => /^-[A-Za-z]*x[A-Za-z]*$|^--extract$/.test(a))) add(option(args, ['-C', '--directory']) || '.', 'extract')
    else if (name === 'unzip' && !args.some(a => /^-[ltpvZ]\b/.test(a))) add(option(args, ['-d']) || '.', 'extract')
    else if (name === '7z' && args.some(a => /^(?:x|e)$/.test(a))) add(option(args, ['-o']) || '.', 'extract')

    for (const path of redirects) if (!seen.has(path)) add(path, 'redirect')
    const inputDocs = [...(segment.previous === '|' ? pipedDocs : []), ...docs]
    if (depth < 2 && SHELLS.test(name)) {
      const recurse = body => parseLevel(body, name, baseDir ?? cwd, { baseDir, cwdUnknown, skipVerify }, depth + 1, out)
      for (const doc of inputDocs) if (doc.body) recurse(doc.body)
      const flag = args.findIndex(arg => /^(?:-[a-z]*c[a-z]*|\/c|--command)$/i.test(arg))
      if (flag >= 0 && /^(?:"|')/.test(args[flag + 1] ?? '')) recurse(unquote(args[flag + 1]))
    } else if (INTERPRETERS.test(name) && inputDocs.some(doc => !doc.ps && doc.body !== undefined)) add('(stdin-script)', 'stdin-script', undefined, true)
    // A here-string or heredoc on the left of a pipeline can itself feed a
    // shell. Inspect that body conservatively, including prefixed emitters.
    pipedDocs = segment.next === '|' ? inputDocs : []
  }
}

/** Parse shell writes without executing commands. Each write keeps its own cwd. */
export function extractShellWrites(tool, args, cwd) {
  const extracted = extractCommand(tool, args)
  if (!extracted) return null
  const out = { known: [], unknown: [] }
  parseLevel(extracted.command, tool, cwd, {}, 0, out)
  return out.known.length || out.unknown.length ? out : null
}
