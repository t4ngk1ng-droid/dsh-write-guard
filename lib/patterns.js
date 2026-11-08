/**
 * Detection rules for content that an agent is about to write.
 *
 * Each rule carries a severity (0-100), one or more regular expressions, and
 * an optional `probe`: a lowercase substring that must appear in the text
 * before the regexes are tried. The probe turns the hot path from "25 regex
 * passes over every write" into "one lowercase scan plus a handful of regex
 * passes", which matters when an agent writes a large file.
 *
 * Regexes use bounded quantifiers only (`{0,200}`, `[^\n]{0,200}`) so a single
 * pathological line cannot trigger catastrophic backtracking.
 *
 * This is a heuristic layer, not a signature engine: it targets the shapes
 * that matter for the "agent writes a malicious file" threat model —
 * download-and-execute, encoded payloads, persistence, credential access,
 * reverse shells, defense evasion, and double-extension trickery.
 */

/** Extensions that are executable content: never written silently. */
export const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.scr', '.sys', '.com', '.msi', '.msp', '.mst', '.cpl',
  '.ocx', '.drv', '.efi', '.pif', '.lnk', '.job', '.gadget', '.msc', '.chm',
  '.vbs', '.vbe', '.jse', '.wsf', '.wsc', '.wsh', '.hta', '.jar', '.class', '.xll',
])

/** Script extensions that run on a normal double-click or `sh` — confirm first. */
export const SCRIPT_EXTENSIONS = new Set([
  '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.sh', '.bash', '.zsh', '.ksh',
  '.command', '.reg', '.scf', '.url',
])

/** Source extensions common in normal projects — no base score, content decides. */
export const LOW_RISK_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.vue', '.svelte', '.php',
  '.py', '.pyw', '.pl', '.rb', '.lua', '.go', '.rs', '.c', '.cc', '.cpp',
  '.h', '.hpp', '.java', '.kt', '.cs', '.swift', '.sql', '.html', '.htm',
  '.xml', '.yaml', '.yml',
])

/**
 * Documentation extensions. A README that quotes a malicious command is
 * evidence, not an attack — `docPolicy: downgrade` turns a deny into an ask
 * so a human can read the example before anything runs.
 */
export const DOC_EXTENSIONS = new Set([
  '.md', '.markdown', '.txt', '.rst', '.adoc', '.org', '.tex',
])

/** Archive/document extensions that hide an executable in a double extension. */
const DECOY_EXTENSIONS = 'pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|bmp|txt|rtf|csv|mp3|mp4|avi|mov|zip|rar|7z|tar|gz'

/** @typedef {{ id: string, category: string, severity: number, title: string, probe?: string[], patterns: RegExp[] }} Rule */

/** @type {Rule[]} */
export const RULES = [
  // ---------------------------------------------------------------------
  // Download and execute
  // ---------------------------------------------------------------------
  {
    id: 'download-exec-pipe',
    category: 'download-execute',
    severity: 95,
    title: '下载内容直接管道到解释器',
    probe: ['curl', 'wget', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'iex', 'invoke-expression'],
    patterns: [
      /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:\/(?:usr\/)?bin\/)?(?:bash|sh|zsh|python3?|perl|ruby|php|node|iex|Invoke-Expression|powershell|pwsh)\b/i,
      /\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b/i,
      /\b(?:IEX|Invoke-Expression)\b[^\n]{0,60}\(?[\s]*\b(?:New-Object|iwr|Invoke-WebRequest|curl|wget)\b/i,
      // Process substitution and command-substitution execution:
      // `bash <(curl ...)` and `eval "$(curl ...)"` never contain a pipe.
      /\b(?:bash|sh|zsh|dash)\b\s*<\(\s*(?:curl|wget)\b/i,
      /\b(?:eval|source)\b[^\n]{0,80}(?:<|\$)\(\s*(?:curl|wget)\b/i,
    ],
  },
  {
    id: 'download-exec-api',
    category: 'download-execute',
    severity: 90,
    title: '通过 .NET 网络 API 下载并执行',
    probe: ['downloadstring', 'downloaddata', 'downloadfile'],
    patterns: [
      // A download API alone is common legitimate code. Require a nearby
      // execution primitive, in either order, instead of denying every
      // WebClient/HttpClient use. The bounded span also covers multi-line calls.
      /\b(?:IEX|Invoke-Expression)\b[\s\S]{0,300}\b(?:DownloadString|DownloadData)\b/i,
      /\b(?:DownloadString|DownloadData)\b[\s\S]{0,300}\b(?:IEX|Invoke-Expression)\b/i,
      /\bDownloadFile\b[\s\S]{0,300}\b(?:Start-Process|Invoke-Item)\b/i,
      /\b(?:Start-Process|Invoke-Item)\b[\s\S]{0,300}\bDownloadFile\b/i,
    ],
  },
  {
    id: 'download-exec-lolbin',
    category: 'download-execute',
    severity: 90,
    title: '使用系统 LOLBin 下载或执行远程内容',
    probe: ['certutil', 'bitsadmin', 'mshta', 'regsvr32', 'rundll32', 'wmic', 'installutil'],
    patterns: [
      /\bcertutil\s+(?:-urlcache|-decode|-decodehex|-f)\b/i,
      /\bbitsadmin\s+\/transfer\b/i,
      /\bmshta\s+(?:https?:|javascript:|vbscript:)/i,
      /\bregsvr32\b[^\n]{0,80}(?:scrobj\.dll|\/i:)/i,
      /\brundll32\b[^\n]{0,80}(?:javascript:|https?:)/i,
      /\bwmic\s+process\s+call\s+create\b/i,
      /\binstallutil\b[^\n]{0,80}\/logfile=/i,
    ],
  },
  {
    id: 'download-exec-shell',
    category: 'download-execute',
    severity: 85,
    title: 'Shell 下载后执行',
    probe: ['powershell', 'pwsh', 'python', 'perl', 'ruby'],
    patterns: [
      /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\n]{0,160}-(?:c|command)\b[^\n]{0,160}(?:http|webrequest|download)/i,
      /\b(?:python3?|perl|ruby)\s+-[ce]\s+["'][^\n]{0,200}(?:urlopen|requests\.get|LWP::Simple|open-uri)/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Encoded / obfuscated payloads
  // ---------------------------------------------------------------------
  {
    id: 'encoded-powershell',
    category: 'encoded-payload',
    severity: 85,
    title: 'PowerShell 编码命令',
    probe: ['powershell', 'pwsh', 'frombase64string'],
    patterns: [
      /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\n]{0,120}-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+[A-Za-z0-9+/=]{40,}/i,
      /\$[A-Za-z_][\w]*\s*=\s*["'][A-Za-z0-9+/=]{200,}["'][^\n]{0,40}\[(?:System\.)?Convert\]::FromBase64String/i,
    ],
  },
  {
    id: 'base64-decode-exec',
    category: 'encoded-payload',
    severity: 80,
    title: '解码 Base64 并执行',
    probe: ['frombase64string', 'base64'],
    patterns: [
      // Decoding configuration or a certificate is not execution. Keep the
      // high-severity rule for decode + execute/load combinations only.
      /\bFromBase64String\b[\s\S]{0,400}\b(?:iex|Invoke-Expression|Start-Process|Add-Type|Assembly::Load)\b/i,
      /\b(?:iex|Invoke-Expression|Start-Process|Add-Type|Assembly::Load)\b[\s\S]{0,400}\bFromBase64String\b/i,
      /\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:\/(?:usr\/)?bin\/)?(?:bash|sh|python3?|perl|ruby|node)\b/i,
    ],
  },
  {
    id: 'encoded-executable',
    category: 'encoded-payload',
    severity: 90,
    title: 'Base64/十六进制编码的可执行文件头',
    probe: ['tvqq', 'f0vmrg', '4d5a9000', '7f454c46'],
    patterns: [
      /\bTVqQ[A-Za-z0-9+/_-]{28,}={0,2}(?![A-Za-z0-9+/_=-])/,
      /\bf0VMRg[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/_=-])/,
      /\b(?:4d5a9000|7f454c46)[0-9a-fA-F]{248,}\b/i,
    ],
  },
  {
    id: 'long-opaque-blob',
    category: 'encoded-payload',
    severity: 55,
    title: '超长无结构编码串',
    // No probe: a 600-char base64 blob has no keyword to look for.
    patterns: [/["'][A-Za-z0-9+/]{600,}={0,2}["']/],
  },
  {
    id: 'obfuscation-char-array',
    category: 'obfuscation',
    severity: 60,
    title: '字符数组拼接混淆',
    probe: ['[char]', '-join', '\\x'],
    patterns: [
      /(?:\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*\+?\s*){6,}/i,
      /\[\s*(?:char|int)\s*\[\s*\]\s*\]\s*\([^)\n]{40,}\b-join\b/i,
      /-join\s*\(\s*\(?\s*\[char/i,
      /(?:\\x[0-9a-fA-F]{2}){30,}/,
    ],
  },
  {
    id: 'obfuscation-long-line',
    category: 'obfuscation',
    severity: 30,
    title: '单行超长无换行内容',
    // No probe: this rule is about shape, not vocabulary.
    patterns: [],
  },

  // ---------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------
  {
    id: 'persistence-run-key',
    category: 'persistence',
    severity: 80,
    title: '写入注册表自启动项',
    probe: ['currentversion\\run', 'new-itemproperty', 'reg add'],
    patterns: [
      /(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\[^\n]{0,120}CurrentVersion\\Run\b/i,
      /\bNew-ItemProperty\b[^\n]{0,160}(?:CurrentVersion\\Run|\\Run(?:Once)?\b)/i,
      /\breg\s+add\b[^\n]{0,160}\\\\Run\b/i,
    ],
  },
  {
    id: 'persistence-scheduled-task',
    category: 'persistence',
    severity: 75,
    title: '创建计划任务',
    probe: ['schtasks', 'scheduledtask'],
    patterns: [
      /\bschtasks\s+\/create\b/i,
      /\bRegister-ScheduledTask\b/i,
      /\bNew-ScheduledTask(?:Action|Trigger|Principal)?\b/i,
    ],
  },
  {
    id: 'persistence-startup-folder',
    category: 'persistence',
    severity: 75,
    title: '写入启动目录',
    probe: ['startup'],
    patterns: [
      /[\\/]Start(?:up)?\s+Menu[\\/]Programs[\\/]Startup/i,
      /[\\/]AppData[\\/]Roaming[\\/]Microsoft[\\/]Windows[\\/]Start Menu[\\/]Programs[\\/]Startup/i,
      /\bStartupApproved\b/i,
    ],
  },
  {
    id: 'persistence-service',
    category: 'persistence',
    severity: 80,
    title: '创建或修改系统服务',
    probe: ['sc create', 'sc.exe create', 'new-service', 'register-service'],
    patterns: [
      /\bsc(?:\.exe)?\s+create\s+\w+/i,
      /\bNew-Service\b/i,
      /\bRegister-Service\b/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Credential and data theft
  // ---------------------------------------------------------------------
  {
    id: 'credential-browser',
    category: 'credential-theft',
    severity: 95,
    title: '读取浏览器凭证库',
    probe: ['login data', 'local state', 'user data', 'cookies.sqlite'],
    patterns: [
      /[\\/]Login Data\b/i,
      /\bLogin Data\b[^\n]{0,100}\b(?:copy|open|read|decrypt|sqlite)\b/i,
      /\b(?:copy|open|read|decrypt|sqlite)\b[^\n]{0,100}\bLogin Data\b/i,
      /\bLocal State\b[^\n]{0,120}\bencrypted_key\b/i,
      /\b(?:Chrome|Edge|Brave|Opera)\b[^\n]{0,160}\bUser Data\b[^\n]{0,160}\b(?:Login Data|Local State|Cookies)\b/i,
      /\bcookies\.sqlite\b/i,
    ],
  },
  {
    id: 'credential-os',
    category: 'credential-theft',
    severity: 95,
    title: '读取系统凭证或内存凭据',
    probe: ['lsass', 'mimikatz', 'sekurlsa', 'kerberos::', 'vssadmin', 'reg save', 'ntds.dit'],
    patterns: [
      /\blsass(?:\.exe)?\b[^\n]{0,120}\b(?:dump|minidump|comsvcs|procdump|OpenProcess|ProcessAccess)\b/i,
      /\b(?:dump|minidump|comsvcs|procdump|OpenProcess|ProcessAccess)\b[^\n]{0,120}\blsass(?:\.exe)?\b/i,
      /\bmimikatz\b|\bsekurlsa\b|\bkerberos::/i,
      /\bvssadmin\b[^\n]{0,80}\bshadows?\b/i,
      /\breg\s+save\b[^\n]{0,80}\b(?:SAM|SYSTEM|SECURITY)\b/i,
      /\bNTDS\.dit\b/i,
    ],
  },
  {
    id: 'credential-wallet',
    category: 'credential-theft',
    severity: 90,
    title: '读取加密钱包或 SSH 私钥',
    probe: ['wallet.dat', 'metamask', '.ssh', 'exodus'],
    patterns: [
      /\bwallet\.dat\b/i,
      /\bMetaMask\b[^\n]{0,80}\b(?:seed|vault|extension)\b/i,
      /\.ssh[\\/]id_(?:rsa|ed25519|ecdsa)\b/i,
      /\bExodus[\\/]/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Reverse shells
  // ---------------------------------------------------------------------
  {
    id: 'reverse-shell',
    category: 'reverse-shell',
    severity: 95,
    title: '反弹 Shell',
    probe: ['/dev/tcp', 'tcpclient', 'nc', 'ncat', 'netcat', 'socat', 'bash -i', 'socket'],
    patterns: [
      /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/,
      /\bNew-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\b[\s\S]{0,1000}\b(?:IEX|Invoke-Expression|cmd\.exe|ProcessStartInfo|\/bin\/(?:ba)?sh)\b/i,
      /\b(?:IEX|Invoke-Expression|cmd\.exe|ProcessStartInfo|\/bin\/(?:ba)?sh)\b[\s\S]{0,1000}\bNew-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\b/i,
      /\b(?:nc|ncat|netcat)\s+(?:-e|--exec|-c)\s+(?:\/bin\/)?(?:sh|bash|cmd)/i,
      /\bsocat\b[^\n]{0,60}\bexec:/i,
      /\bbash\s+-i\s+>&\s*\/dev\/tcp/i,
      /\bpython3?\b[^\n]{0,160}\bsocket\b[^\n]{0,160}\bconnect\b[^\n]{0,160}\b(?:subprocess|pty|dup2|\/bin\/(?:ba)?sh)\b/i,
      /\bpython3?\b[^\n]{0,160}\bsocket\b[^\n]{0,160}\b(?:subprocess|pty|dup2)\b[^\n]{0,160}\bconnect\b/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Defense evasion / AV tampering
  // ---------------------------------------------------------------------
  {
    id: 'av-tamper',
    category: 'defense-evasion',
    severity: 100,
    title: '关闭或绕过杀毒/日志',
    probe: ['set-mppreference', 'add-mppreference', 'advfirewall', 'wevtutil', '.evtx', 'bcdedit'],
    patterns: [
      /\bSet-MpPreference\b[^\n]{0,160}(?:Disable|Exclusion)/i,
      /\bAdd-MpPreference\b[^\n]{0,160}ExclusionPath/i,
      /\bnetsh\s+advfirewall\s+set\s+(?:allprofiles|currentprofile)\s+state\s+off/i,
      /\bwevtutil\s+cl\b/i,
      /Remove-Item[^\n]{0,120}\.evtx/i,
      /\bbcdedit\b[^\n]{0,120}nointegritychecks/i,
    ],
  },
  {
    id: 'execution-policy-bypass',
    category: 'defense-evasion',
    severity: 60,
    title: '绕过执行策略或隐藏窗口',
    probe: ['executionpolicy', 'windowstyle', '-w hidden'],
    patterns: [
      /-ExecutionPolicy\s+Bypass/i,
      /-WindowStyle\s+Hidden/i,
      /-w\s+hidden\b/i,
      // -NoProfile -NonInteractive is normal in CI and is not evasion alone.
    ],
  },
  {
    id: 'uac-bypass',
    category: 'privilege-escalation',
    severity: 85,
    title: 'UAC 自动提权绕过',
    probe: ['fodhelper', 'computerdefaults', 'sdclt', 'eventvwr', 'slui'],
    patterns: [
      /\b(?:fodhelper|computerdefaults|sdclt|eventvwr|slui)\b[^\n]{0,80}(?:HKCU|HKEY_CURRENT_USER|shell)/i,
    ],
  },
  {
    id: 'explicit-elevation',
    category: 'privilege-escalation',
    severity: 40,
    title: '显式请求管理员权限',
    probe: ['runas', 'secedit'],
    patterns: [
      /\bStart-Process\b[^\n]{0,120}-Verb\s+RunAs/i,
      /\brunas\s+\/user:/i,
      /\bsecedit\b[^\n]{0,80}\/export/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Office / script host abuse
  // ---------------------------------------------------------------------
  {
    id: 'office-macro',
    category: 'office-macro',
    severity: 75,
    title: 'Office 宏自动执行',
    probe: ['autoopen', 'auto_open', 'autoexec', 'document_open', 'workbook_open', 'workbook_activate', 'vba'],
    patterns: [
      /\bSub\s+(?:AutoOpen|Auto_Open|AutoExec|Document_Open|Workbook_Open|Workbook_Activate)\b/i,
      /\bVBA\b[^\n]{0,120}\b(?:Shell|CreateObject)\b/i,
    ],
  },
  {
    id: 'wscript-shell',
    category: 'office-macro',
    severity: 60,
    title: 'Windows Script Host 执行命令',
    probe: ['wscript.shell', 'shell.application', 'activexobject'],
    patterns: [
      /\bWScript\.Shell\b/i,
      /\bCreateObject\s*\(\s*["']WScript\.Shell["']\s*\)/i,
      /\bShell\.Application\b[^\n]{0,80}\bShellExecute\b/i,
      /\bActiveXObject\s*\(\s*["'](?:WScript\.Shell|Shell\.Application)["']\s*\)/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Self-propagation
  // ---------------------------------------------------------------------
  {
    id: 'propagation-usb',
    category: 'propagation',
    severity: 80,
    title: 'U 盘/盘符遍历传播',
    probe: ['logicaldisk', 'get-psdrive', 'autorun.inf'],
    patterns: [
      /\bfor\s+\/f\b[^\n]{0,120}\bwmic\s+logicaldisk/i,
      /\bGet-PSDrive\b[^\n]{0,120}\b(?:Copy-Item|robocopy)\b/i,
      /\bautorun\.inf\b/i,
    ],
  },

  // ---------------------------------------------------------------------
  // Archives
  // ---------------------------------------------------------------------
  {
    id: 'archive-extract-exec',
    category: 'archive',
    severity: 80,
    title: '解压后直接执行',
    probe: ['expand-archive', 'tar -x', 'unzip', '7z x', 'extractto', '解开'],
    patterns: [
      /\bExpand-Archive\b[\s\S]{0,300}\b(?:Start-Process|Invoke-Item|&)\b/i,
      /\b(?:unzip|7z\s+x|tar\s+-x)\b[\s\S]{0,300}\b(?:chmod\s+\+x|\.\/|Start-Process)\b/i,
      /\b(?:tar|unzip|7z)\b[^\n]{0,160}\b(?:\.exe|\.dll|\.ps1|\.sh)\b/i,
    ],
  },
  {
    id: 'archive-password',
    category: 'archive',
    severity: 45,
    title: '带密码创建归档',
    probe: ['-p', 'password', 'passphrase'],
    patterns: [
      /\b(?:zip|7z)\b[^\n]{0,120}\s-p\S+/i,
      /\b(?:7z|zip|rar)\b[^\n]{0,120}\b(?:-p|-password)\b/i,
    ],
  },
]

/** Rule ids that are informational only. */
export const RULE_IDS = RULES.map((r) => r.id)

/** Paths that hide an executable behind a document extension. */
export const DOUBLE_EXTENSION_RE = new RegExp(
  `\\.(?:${DECOY_EXTENSIONS})\\.(?:exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|hta|lnk|msi)$`,
  'i',
)

/** Archive/container extensions: content cannot be inspected as text. */
export const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.7z', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.zst',
  '.cab', '.iso', '.img', '.dmg', '.vhd', '.vhdx', '.wim', '.esd',
])

/** Text-like extensions where a binary magic header is a strong signal. */
export const TEXT_LIKE_EXTENSIONS = new Set([
  '.md', '.markdown', '.mdx', '.txt', '.rst', '.json', '.yaml', '.yml',
  '.csv', '.log', '.ini', '.cfg', '.conf', '.xml', '.html', '.htm',
])

/**
 * File magic seen as text. An agent that writes a PE or ELF header into a
 * `.txt` is not writing documentation.
 */
export const MAGIC_SIGNATURES = [
  { id: 'pe', label: 'PE/Windows 可执行文件', probe: 'mz' },
  { id: 'elf', label: 'ELF 可执行文件', probe: '\u007fELF' },
  { id: 'macho-be', label: 'Mach-O 可执行文件', probe: '\u00fe\u00ed\u00fa\u00ce' },
  { id: 'macho-le', label: 'Mach-O 可执行文件', probe: '\u00ce\u00fa\u00ed\u00fe' },
  { id: 'zip', label: 'ZIP 归档', probe: 'PK\u0003\u0004' },
  { id: 'rar', label: 'RAR 归档', probe: 'rar!\u001a\u0007' },
  { id: '7z', label: '7z 归档', probe: '7z\u00bc\u00af\u0027\u001c' },
  { id: 'gzip', label: 'GZIP 归档', probe: '\u001f\u008b' },
]

/**
 * Letters that render identically to Latin but are not Latin. NFKC leaves
 * these alone, so `ІЕХ` (Cyrillic) would otherwise sail past every keyword
 * rule. Only the confusable set is mapped; real Cyrillic text is unaffected
 * because we never rewrite words, only individual opaque characters.
 */
export const HOMOGLYPH_MAP = new Map([
  ['а', 'a'], // а
  ['е', 'e'], // е
  ['о', 'o'], // о
  ['р', 'p'], // р
  ['с', 'c'], // с
  ['у', 'y'], // у
  ['х', 'x'], // х
  ['і', 'i'], // і
  ['ј', 'j'], // ј
  ['ѕ', 's'], // ѕ
  ['һ', 'h'], // һ
  ['ԁ', 'd'], // ԁ
  ['ɡ', 'g'], // ɡ
  ['ӏ', 'l'], // ӏ
  ['α', 'a'], // α
  ['ο', 'o'], // ο
  ['ρ', 'p'], // ρ
  ['ν', 'v'], // ν
  ['ι', 'i'], // ι
  ['κ', 'k'], // κ
  ['τ', 't'], // τ
  ['υ', 'u'], // υ
  ['χ', 'x'], // χ
])

/** Matches any single character present in HOMOGLYPH_MAP. */
export const HOMOGLYPH_RE = new RegExp(
  `[${[...HOMOGLYPH_MAP.keys()].map((ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')}]`,
  'gu',
)
