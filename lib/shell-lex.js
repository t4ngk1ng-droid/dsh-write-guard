// A bounded shell lexer, not an evaluator. Operators are recognized before
// words are unquoted. A literal cmdlet name in an argument stays an argument.
function escapeChar(ps) { return ps ? '`' : '\\' }

function wordEnd(text, at, ps, inline) {
  let i = at, quote = ''
  while (i < text.length) {
    const ch = text[i]
    if (ch === escapeChar(ps) && quote !== "'") { i += Math.min(2, text.length - i); continue }
    if (quote) {
      if (ch === quote) {
        if (ps && quote === "'" && text[i + 1] === "'") { i += 2; continue }
        // Preserve the historical multiline Python/PS spelling where inner
        // string literals are unescaped, e.g. print("none") on its own line.
        // Never use a later statement's quote to consume an outer redirect.
        if (inline && quote === '"' && /[=(,r]/.test(text[i - 1]) && /[^\s";|&]/.test(text[i + 1] ?? ' ')) {
          const pair = /^[^"\r\n]*"(?=[,)\]])/.exec(text.slice(i + 1))
          if (pair) { i += 1 + pair[0].length; continue }
        }
        quote = ''
      }
      i++
      continue
    }
    if (ch === '"' || ch === "'") { quote = ch; i++; continue }
    if (/[\s;&|<>]/.test(ch)) break
    i++
  }
  return i
}

function hereString(text, at) {
  const start = /^@(['"])[ \t]*\r?\n/.exec(text.slice(at))
  if (!start) return null
  const bodyStart = at + start[0].length
  const close = new RegExp(`^${start[1]}@`, 'gm')
  close.lastIndex = bodyStart
  const end = close.exec(text)
  return { body: text.slice(bodyStart, end?.index).replace(/\r?\n$/, ''), end: end ? close.lastIndex : text.length }
}

export function lexShell(text, ps) {
  const segments = [], pendingDocs = []
  let words = [], redirects = [], documents = [], previous = '', start = 0, target = null
  function finish(end, next) {
    if (words.length || redirects.length || documents.length) {
      segments.push({ words, redirects, documents, previous, next, text: text.slice(start, end).trim() })
      previous = next
    } else if (!['&&', '||', '|'].includes(previous)) previous = next
    words = []; redirects = []; documents = []; target = null
  }
  function token(raw, at, body) {
    if (target) {
      target.word = raw
      if (target.doc) { documents.push(target); pendingDocs.push(target) }
      else if (target.output) redirects.push(target)
      target = null
    } else {
      words.push({ raw, at })
      if (body !== undefined) documents.push({ body, ps: true })
    }
  }
  for (let i = 0; i < text.length;) {
    const ch = text[i], pair = text.slice(i, i + 2)
    if (ch === '\n' || ch === ';' || ch === '|' || pair === '&&' || (!ps && ch === '&' && pair !== '&>')) {
      const op = pair === '&&' || pair === '||' ? pair : ch
      finish(i, op); i += op.length
      if (ch === '\n') {
        for (const doc of pendingDocs) {
          const name = doc.word.replace(/^(['"])(.*)\1$/, '$2'), begin = i
          while (i < text.length) {
            let eol = text.indexOf('\n', i)
            if (eol === -1) eol = text.length
            const line = text.slice(i, eol).replace(/\r$/, '')
            if ((doc.tabs ? line.replace(/^\t+/, '') : line) === name) {
              doc.body = text.slice(begin, i).replace(/\r?\n$/, '')
              i = Math.min(text.length, eol + 1); break
            }
            i = Math.min(text.length, eol + 1)
          }
        }
        pendingDocs.length = 0
      }
      start = i; continue
    }
    if (/\s/.test(ch)) { i++; continue }
    if (ps && pair === '<#') {
      const e = text.indexOf('#>', i + 2); i = e < 0 ? text.length : e + 2
      if (!words.length && !redirects.length) start = i
      continue
    }
    if (ch === '#' && (i === 0 || /[\s;|&()]/.test(text[i - 1]))) {
      const e = text.indexOf('\n', i)
      finish(i, '\n'); i = e < 0 ? text.length : e; start = i; continue
    }
    if (!ps && !words.length && !target && pair === '[[' && /\s/.test(text[i + 2] || '')) {
      let j = i + 2
      // Inside [[ ]], comparisons and boolean operators are not redirects or lists.
      while (j < text.length) {
        if (text.startsWith(']]', j) && /\s/.test(text[j - 1]) && (!text[j + 2] || /[\s;&|<>]/.test(text[j + 2]))) { j += 2; break }
        j = Math.max(j + 1, wordEnd(text, j, false, false))
      }
      token(text.slice(i, j), i); i = j; continue
    }
    if (ps && ch === '@' && /['"]/.test(text[i + 1] ?? ' ')) {
      const doc = hereString(text, i)
      if (doc) { token(text.slice(i, doc.end), i, doc.body); i = doc.end; continue }
    }
    if (ch === '>' || ch === '<' || pair === '&>') {
      const m = /^(?:<<<|<<-|<<|&>>|&>|>>|>\||<>|[<>]&|[<>])/.exec(text.slice(i))[0]
      // An adjacent descriptor is part of the operator, not a positional value.
      if (words.length && /^\d+$/.test(words.at(-1).raw) && words.at(-1).at + words.at(-1).raw.length === i) words.pop()
      target = { at: i, output: m.includes('>') && !['>&', '<>'].includes(m), doc: !ps && (m === '<<' || m === '<<-'), tabs: m === '<<-' }
      i += m.length; continue
    }
    if (ps && ch === '&') { token('&', i); i++; continue }
    const inline = words.length > 1 && /^-[ce]$/.test(words.at(-1).raw) && /(?:^|[/\\])(?:python3?|pypy3?|node|deno|bun|perl|ruby|php|Rscript)(?:\.exe)?$/i.test(words[0].raw) && /^"\r?\n/.test(text.slice(i))
    const end = Math.max(i + 1, wordEnd(text, i, ps, inline))
    token(text.slice(i, end), i); i = end
  }
  finish(text.length, '')
  return segments
}
