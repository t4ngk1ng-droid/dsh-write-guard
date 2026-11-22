import { isAbsolute, resolve } from 'node:path'

// One abstract cwd per exit edge: undefined = unreachable, null = unknown,
// '' = entry directory. Merging distinct directories must never guess one.
function merge(a, b) {
  if (a === undefined) return b
  if (b === undefined || a === b) return a
  return null
}

function cdTarget(text, bash, cwd, entry, usesCdPath) {
  // Only a single literal argument; avoid expansions, provider paths,
  // switches, and shell-dependent escape/tilde semantics.
  const args = bash ? /^cd\s+(?:--\s+)?(.+)$/.exec(text) : /^(?:cd|Set-Location)\s+(?:-(?:Path|LiteralPath)\s+)?(.+)$/i.exec(text)
  if (!args) return null
  const match = /^(?:'([\w .\-/]+)'|"([\w .\-/]+)"|([\w.\-/]+))$/.exec(args[1])
  if (!match) return null
  const target = match[1] ?? match[2] ?? match[3]
  if (!target || target.startsWith('-') || (process.platform === 'win32' && target.startsWith('/'))) return null
  if (!isAbsolute(target) && (cwd === null || (!entry && !cwd))) return null
  if (bash && usesCdPath && !/^(?:\.{1,2}(?:\/|$)|\/)/.test(target)) return null
  return resolve(cwd || entry || '.', target)
}

/** Track simple lists only. State is local to a single shell invocation. */
export function createShellFlow(tool, entry) {
  const bash = tool === 'bash' || tool === 'sh' || tool === 'zsh' || tool === 'dash'
  let success = '', failure
  let usesCdPath = Boolean(process.env.CDPATH)
  let inPipe = false, pipeCwd, pipeSkipSuccess, pipeSkipFailure
  return (statement, preceding, following) => {
    let input, bypassSuccess, bypassFailure
    if (preceding === '&&') {
      input = success
      bypassFailure = failure
    } else if (preceding === '||') {
      input = failure
      bypassSuccess = success
    } else {
      input = merge(success, failure)
    }
    if (inPipe) {
      input = pipeCwd
      bypassSuccess = pipeSkipSuccess
      bypassFailure = pipeSkipFailure
    } else if (following === '|') {
      pipeCwd = input
      pipeSkipSuccess = bypassSuccess
      pipeSkipFailure = bypassFailure
    }
    const text = statement.trim()
    // Keep the pre-scan even for a predictable short circuit. This hint may
    // excuse ENOENT only; if the target exists, the post-scan still runs.
    const skipped = input === undefined
    // Keep the branch's last reachable directory for inspecting its target.
    const location = skipped ? merge(bypassSuccess, bypassFailure) : input
    let ok = input, err = input
    if (!skipped) {
      if (bash && /\bCDPATH\b/.test(text)) usesCdPath = true
      if ((bash ? /^cd(?:\s|$)/ : /^(?:cd|Set-Location)(?:\s|$)/i).test(text)) {
        ok = cdTarget(text, bash, input, entry, usesCdPath)
        // PowerShell location providers may report non-terminating errors.
        if (!bash) ok = merge(ok, input)
      } else if (/^(?:pushd|popd|Push-Location|Pop-Location|chdir|sl)(?:\s|$)/i.test(text)) {
        ok = null
      } else if (bash && /^(?:test[ \t]+-d[ \t]+\.|\[[ \t]+-d[ \t]+\.[ \t]+\])$/.test(text)) {
        err = undefined
      }
    }
    if (inPipe || following === '|') {
      // Pipeline stages do not establish a new cwd in the caller. Where a
      // shell can run a final location-changing stage in-process, be cautious.
      ok = ok === input ? pipeCwd : merge(pipeCwd, ok)
      err = pipeCwd
    }
    inPipe = following === '|'
    success = merge(ok, bypassSuccess)
    failure = merge(err, bypassFailure)
    return { baseDir: location || undefined, cwdUnknown: location === null, skipVerify: skipped }
  }
}
