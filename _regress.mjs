import { extractShellWrites } from './lib/shell.js'
const cwd = 'C:/w'
const cases = [
  ['tee',            'bash', 'echo payload | tee x.ps1'],
  ['tee -a 多目标',  'bash', 'echo p | tee -a a.txt b.txt'],
  ['Tee-Object',     'pwsh', 'Get-Content a | Tee-Object -FilePath out.ps1'],
  ['Set-Content 顺序','pwsh','Set-Content -Value "x" -Path s1.ps1'],
  ['Set-Content 管道','pwsh','Get-Content a | Set-Content s2.ps1'],
  ['WriteAllText',   'pwsh', '[IO.File]::WriteAllText("w.txt", $var)'],
  ['New-Item -Value','pwsh', 'New-Item -Path n.txt -Value $var'],
  ['Out-File 无值',  'pwsh', 'Get-Content a | Out-File o.ps1'],
  ['tar 默认目录',   'bash', 'tar -xzf a.tgz'],
  ['unzip',          'bash', 'unzip pkg.zip'],
  ['Expand-Archive', 'pwsh', 'Expand-Archive -Path p.zip'],
  ['irm -OutFile',   'pwsh', 'irm https://e.com/x -OutFile d.ps1'],
  ['curl -o',        'bash', 'curl -o c.ps1 https://e.com/x'],
  ['反向 heredoc',   'bash', "cat <<EOF > r.txt\nhi\nEOF"],
  ['bash -c 递归',   'bash', 'bash -c "echo x > inner.txt"'],
  ['here-string 管道bash','pwsh',"@'\necho x > hs.txt\n'@ | bash"],
  ['python -c 遮罩', 'pwsh', 'python -c "print(d[0:])"'],
  ['printf 格式串',  'bash', "printf '%s' payload > p.txt"],
  ['直接重定向',     'bash', 'echo hi > d.txt'],
]
let miss = 0
for (const [label, tool, cmd] of cases) {
  const r = extractShellWrites(tool, { command: cmd }, cwd)
  const paths = r ? [...r.known.map(w=>w.path), ...r.unknown.map(w=>w.path)] : []
  const ok = paths.length > 0
  if (!ok) miss++
  console.log(`${ok ? 'ok  ' : 'MISS'} ${label.padEnd(22)} ${JSON.stringify(paths)}`)
}
console.log(`\n漏检 ${miss}/${cases.length}`)
