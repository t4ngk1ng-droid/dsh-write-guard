# dsh-write-guard

**内容级写入防护插件 for DeepSeek Harness。** 现有的权限插件看"写到哪、跑什么命令"；这个看**即将写进文件的字节是什么**，并在落盘后再核对一次。

在 `tools/pre-execute` 拦 `write` / `edit` / `str_replace_editor`，同时解析 `bash` / `pwsh` 命令里的写文件行为；在 `tools/post-execute` 读回文件做哈希校验和全文二次扫描。被拒载荷进隔离区，所有决策进哈希链审计，插件启动时校验自身文件。

> 它不是杀毒软件。它是"在 Agent 落盘前多一道内容检查，落盘后再核对一次"——降低概率并留下证据，不证明安全。

**给非开发者看的版本**：[中文介绍](GUIDE-zh.md) —— 解决什么问题、怎么工作、默认策略、明确做不到什么，不需要读代码。

## 为什么需要它

典型威胁不是 Agent 执行一条恶意命令，而是 Agent **写下一个恶意文件**，然后由用户、计划任务、开机启动或另一个程序执行它：

```
用户: 帮我从那个仓库拉个安装脚本，修一下 Windows 兼容
Agent: （从 README 里抄一段带 IEX DownloadString 的 PowerShell，写进 setup.ps1）
用户: （双击运行）
```

路径规则拦不住这个——路径看起来完全正常，命令也不是 `bash -c`。只有看内容才能发现。

## 能力

| 层面 | 检查 |
|---|---|
| 文件写入 | `write` / `edit` / `str_replace_editor` 的路径、内容、字节 |
| Shell 写入 | heredoc（两种顺序）、`echo/printf >`、`Set-Content`、`Add-Content`、`Out-File`、`Set-Item`、`[IO.File]::WriteAllText`、`New-Item -Value` |
| Shell 未知写入 | `curl -o`、`wget -O`、`Invoke-WebRequest`/`Invoke-RestMethod -OutFile`、certutil/bitsadmin 下载、`Expand-Archive`/`tar -x`/`unzip`/`7z x`（含默认当前目录）、管道输入（`tee`/`Tee-Object`、无 `-Value` 的 `Out-File`）、变量/表达式值、动态路径、通用 `>` 重定向：内容不可静态检查，按来源与目标转人工 |
| 路径 | 可执行扩展名（`.exe/.dll/.scr/.vbs/.hta/.jar/.xll`…）、双扩展名（`invoice.pdf.exe`）、Win32 尾点/尾空格、脚本扩展名 |
| 内容 | 27 条内置规则：下载即执行、编码载荷、混淆、持久化、凭证窃取、反弹 Shell、AV 篡改、UAC 绕过、Office 宏、归档解压执行、传播 |
| 文件头 | PE / ELF / Mach-O / ZIP / RAR / 7z / GZIP magic；可执行头写进文本文件直接拒绝 |
| 编码折叠 | NFKC + 零宽/双向控制字符剥离 + 西里尔/希腊字母混淆映射 |
| 熵 | 长 base64/hex 高熵串（加密或压缩载荷） |
| 分片 | 落盘后读取完整文件重新扫描，多次小改动拼起来的载荷在第二次扫描暴露 |
| 哈希 | `write` 的落盘哈希必须等于批准写入的哈希；不一致说明被其他进程改过 |
| 自定义规则 | 项目级 `write-guard.rules.json`，支持 probe/paths/severity |
| 自校验 | 启动时对自身全部文件（入口、`lib/`、脚本、测试、配置与文档）做指纹，基线写在 `~/.dsh/write-guard/integrity.json` |

## 两道闸门

```
tools/pre-execute
  ├─ write/edit/str_replace_editor → 内容扫描 → allow / ask / deny
  ├─ bash/pwsh → 解析写文件行为
  │     ├─ 已知内容 → 内容扫描
  │     └─ 未知内容（下载/解压/重定向）→ 按目标与来源转人工
  └─ deny 短路；ask 走原生审批

tools/post-execute
  ├─ 读回文件 → sha256 与批准哈希比对
  ├─ 完整文件二次扫描 → 发现分片拼接的载荷
  └─ 不一致或命中 → block，把原因反馈给模型
```

`deny > ask > allow` 合并，最严格的决定生效。

## 安装

尚未发布到 npm 和插件市场，从仓库安装：

```bash
git clone https://github.com/t4ngk1ng-droid/dsh-write-guard.git
dsh plugin --profile web add file:./dsh-write-guard
```

`add` 在 Windows 上依赖 pnpm；没有的话先 `corepack enable pnpm`。

桌面版（`desktop` profile 由 Electron 独占，CLI 不能写入）：

1. `npm pack` 生成 tgz，或直接复制仓库目录
2. 解压到 `~/.dsh/profiles/desktop/node_modules/dsh-write-guard`
3. 在 `~/.dsh/profiles/desktop/package.json` 的 `dependencies` 加 `"dsh-write-guard": "file:../../plugins/dsh-write-guard"`，并把 `dsh-write-guard` 加进 `dsh.profile.bundles`
4. 在 `cordis.patch.yml` 里设 `- id: write-guard` + `config.mode: dry-run`，重启后切 `enforce`

首次运行会在 `~/.dsh/write-guard/` 下建完整性基线；**升级版本后必须删除该目录的 `integrity.json` 再重启**，否则会报 `tampered`（这是设计行为，不是 bug）。

## 配置

`cordis.patch.yml` 里全部可选项，默认值即推荐值。核心几项：

```yaml
- insert:
    - id: write-guard
      name: dsh-write-guard
      config:
        mode: enforce              # enforce | dry-run | off
        blockThreshold: 70         # >= 70 拒绝
        askThreshold: 40           # >= 40 转人工
        maxScanBytes: 524288       # 单次扫描的 UTF-8 字节上限
        maxContentBytes: 33554432  # 硬上限，超过只问不扫
        scriptPolicy: ask          # 裸脚本：ask | allow | deny
        docPolicy: downgrade       # 文档里的命令示例：降为 ask
        shellGuard: true           # 解析 shell 写文件
        shellUnknownPolicy: ask    # 无法检查内容时：ask | allow
        shellChecks:               # 按类别开关，false = 该类不再上报（直接放行）
          redirect: true           # > / >> / &>
          echo: true               # echo / printf 内容写入
          heredoc: true            # heredoc 与 stdin 脚本正文
          tee: true                # tee / Tee-Object
          download: true           # curl -o、iwr/irm -OutFile、certutil、bitsadmin
          extract: true            # tar / unzip / 7z / Expand-Archive
          dotnet: true             # [IO.File]::WriteAllText 等
          cmdlets: true            # Set-Content、Out-File、New-Item、Start-Process
        verifyWrites: true         # 写后哈希校验 + 全文二次扫描
        verifyPolicy: block        # 哈希不符、读取失败或二次扫描升级：block | audit
        entropy: true
        integrity: true
        notify: false              # 通知命令见下
        contentChecks:             # 内容扫描按类别开关，false = 该类不扫描
          download-execute: true   # 下载即执行
          encoded-payload: true    # 编码载荷、高熵串
          obfuscation: true        # 混淆
          persistence: true        # 持久化
          credential-theft: true   # 凭证窃取
          reverse-shell: true      # 反弹 Shell
          defense-evasion: true    # 防御规避
          privilege-escalation: true # 提权
          office-macro: true       # Office 宏
          archive: true            # 解压后执行
          propagation: true        # 传播
          magic: true              # PE/ELF/ZIP 文件头
          binary: true             # 二进制控制字节
          double-extension: true   # 双扩展名
```

**全部开关一览**

| 开关 | 默认 | 关掉之后 |
|---|---|---|
| `mode` | `enforce` | `dry-run` 只记录不拦；`off` 完全关闭 |
| `blockThreshold` / `askThreshold` | 70 / 40 | 调整判定分界 |
| `shellGuard` | true | 完全不解析 shell 写入 |
| `shellChecks.*`（8 类） | true | 该类 shell 写入不再上报 |
| `shellUnknownPolicy` | `ask` | `allow`：内容不可检查的写入直接放行 |
| `verifyWrites` | true | 不做写后校验 |
| `verifyPolicy` | `block` | `audit`：哈希不符只记录 |
| `contentChecks.*`（14 类） | true | 该类内容检测不再扫描 |
| `entropy` | true | 不做高熵串检测 |
| `homoglyph` | true | 不做全角/零宽/西里尔折叠 |
| `blockBinaries` | true | 写可执行扩展名降为 `ask` |
| `scriptPolicy` | `ask` | `allow` / `deny` 裸脚本 |
| `docPolicy` | `downgrade` | `enforce`：文档里的命令示例同样拦截 |
| `quarantine` | true | 被拒载荷不留存 |
| `audit` / `auditHashChain` | true | 不写审计 / 不加哈希链 |
| `integrity` | true | 不做插件自身指纹校验 |
| `notify` | false | 告警通道 |
| `onScannerError` | `ask` | `allow`：扫描出错时放行 |

**先干跑**：`mode: dry-run` 只记录"本来会拦什么"，不实际拦截。跑一两天看审计日志，确认没有误报再切 `enforce`。

## 自定义规则

在项目根（或任意上级目录）放 `write-guard.rules.json`：

```json
{
  "rules": [
    {
      "id": "no-prod-config",
      "title": "禁止写生产配置",
      "severity": 100,
      "category": "custom",
      "probe": ["prod"],
      "paths": ["config/**", "deploy/**"],
      "patterns": ["prod\\.env", "\\.prod\\."]
    }
  ]
}
```

- `probe` 是可选的预筛子串，命中任一才跑正则
- `paths` 是可选的路径 glob，只对匹配目标生效
- `severity` 1-100，参与全局评分
- 自定义规则**不会被文档降级**：`.md` 里命中自定义规则仍然是 deny
- 同 id 与内置规则碰撞会拒绝整个项目规则文件；项目只能增加约束，不能削弱内置检测
- `paths` 以规则文件所在目录为根，绝对路径、`./`、`..` 和嵌套 cwd 都先归一化
- 文件变化按 mtime 自动重载（`watchRules: true`），也可以调 `write_guard_reload`

安全限制：文件 ≤ 256 KB、≤ 200 条规则、单条模式 ≤ 2000 字符。为保持零依赖并杜绝同步 ReDoS，项目模式只接受字面文本和安全的转义原子（例如 `prod\\.env`、`\\d`），不接受分组、交替、量词、环视或反向引用；需要“或”时请写多个 pattern。

## 评分

每条规则有 0-100 的严重度，命中多条时取最高分并加 `5 × (命中数-1)`（上限 +15）。路径、文件头、熵、字节层面的发现也参与取最大值：

| 发现 | 分数 |
|---|---|
| 可执行扩展名 / 双扩展名 / 可执行文件头 / AV 篡改 | 100 |
| 下载即执行、凭证窃取、反弹 Shell | 90-95 |
| 编码载荷、持久化、提权、归档解压执行 | 75-90 |
| 高熵编码串 | 65 |
| 归档头写进文本文件 | 60 |
| 裸脚本扩展名 | 40 |
| 普通源码 | 0（内容规则仍可升级） |

## 工具

- **`write_guard_scan(text, path?)`** — 用同一套引擎手动扫一段内容，不写任何东西
- **`write_guard_status()`** — 配置、计数、规则来源、自校验状态、最近 50 条决策
- **`write_guard_config(set?, clear?)`** — **在对话里直接改开关**，不用编辑配置文件
- **`write_guard_reload()`** — 重新加载项目规则文件
- **`write_guard_verify_chain(file?)`** — 校验审计哈希链，报告第一条断链

### 在 DSH 里改开关

不用编辑 YAML。直接对 Agent 说：

> 「把解压检测关掉」
> 「列出 write-guard 现在哪些开关是关的」
> 「下载检测改成只记录不拦」

Agent 会调用 `write_guard_config`，把改动写进 `<DSH_HOME>/write-guard/config.json` 并**立即生效**，不需要重启。

也可以自己指定参数：

```json
{ "set": { "shellChecks": { "extract": false } } }
{ "set": { "mode": "dry-run" } }
{ "clear": ["shellChecks"] }        // 恢复默认
```

嵌套对象是**按键合并**的：只写 `{ "shellChecks": { "extract": false } }` 不会影响其他 7 类。

需要重启才生效的：`audit`、`quarantine`、`notify`、`integrity` —— 它们对应在装载时创建的对象。

## 证据

```
<DSH_HOME>/write-guard/audit.jsonl       # 每次决策一行，带 prev/hash 链
<DSH_HOME>/write-guard/alerts.jsonl      # 通知记录
<DSH_HOME>/write-guard/quarantine/       # 被拒载荷，UUID 文件名，权限 600
<DSH_HOME>/write-guard/integrity.json    # 插件自身文件指纹基线
```

审计记录示例：

```json
{"ts":"2026-11-08T07:41:02.113Z","event":"write-decision","tool":"bash","source":"shell:echo","target":"payload.ps1","decision":"deny","score":100,"sha256":"…","hits":[{"id":"download-exec-api","severity":90,"title":"通过 .NET 网络 API 下载并执行"}],"prev":"…","hash":"…"}
```

审计超过 5 MB 自动轮转。`write_guard_verify_chain` 能发现中间被删/被改的记录；但哈希链没有外部信任锚，无法证明尾部未被整体截断。

通知：设 `notify: true` 并配 `notifyCommand`，消息通过环境变量 `WG_MESSAGE` 传入，不会拼进命令行。例如（PowerShell + BurntToast）：

```yaml
notify: true
notifyCommand: powershell -NoProfile -Command "New-BurntToastNotification -Text $env:WG_MESSAGE"
```

## 自校验

插件启动时对自身全部文件（`index.js`、`lib/`、`scripts/`、`test/`、配置与文档）做 sha256，与 `~/.dsh/write-guard/integrity.json` 比对。首次运行生成基线；此后任何文件变动（**包括版本号升级**）都报告 `tampered`，不会自动洗白。正常升级需手动删除 `integrity.json` 后重启，让基线重建。

这是**篡改证据**，不是**篡改防护**：能写基线的人也能写插件。但基线在 `~/.dsh` 下，默认 `workspace-write` 沙箱里的 Agent 写不到那里。

## 局限（重要）

1. **启发式，不是签名引擎。** 新变种、强混淆、分片写入都能绕过。二次扫描补上了"写完才看得出"的那一类，但不能证明安全。
2. **Shell 解析是模式匹配，不是完整解析器。** 变量、命令替换和 glob 目标会标记为动态写入并转人工；`python -c`/`node -e` 内的 `open(...)`、`cp`/`mv`、`dd of=`、`awk`/`sed -i` 以及深层嵌套的 `bash -c` 仍无法静态还原。heredoc 的数据正文会遮罩，`bash <<EOF` / `cat <<EOF | bash` 的脚本正文会递归解析，`python`/`node` 等非 shell 解释器的正文转人工；未闭合或动态 delimiter 的 heredoc 仍可能被误读。
3. **不扫描磁盘上已有的文件。** 只管"这次要写什么"和"刚写完的是什么"；已落盘的二进制请用 Windows Defender 或 `dsh-secure-audit`。
4. **`ask` 之后由审批链决定。** 配了 `dsh-auto-review` 是第二个模型在答，否则是你本人。
5. **超限只扫前缀。** `truncatePolicy: allow` 会明确承担未扫描后缀的风险。
6. **成功执行不等于每个分支都写了文件。** `verifyPolicy: block` 下，普通写入缺失仍阻断。对于 Bash 中能静态判断的短路（如 `test -d . || …`），仅宽免未执行分支的 `ENOENT`；已有目标仍重扫，不能判定的分支仍须校验。`cd sub && …` 中的相对目标按 `sub` 校验；目录依赖变量或条件合流而不能确定时，按动态目标策略处理，不猜测落盘位置。PowerShell 内置 cmdlet 明确生效的 `-WhatIf` 和非文件 `Env:` 写入不登记为文件，外层重定向仍单独检查。
7. **写后校验有读取上限。** 大于 `maxVerifyBytes`（默认 8 MB）的目标无法读回校验，`verifyPolicy: block` 下会被阻断；要常规写入更大的文件，请调高该上限或改用 `audit`。

## 推荐组合

```
write-guard（内容 + shell + 写后校验）
  + permission-rules（路径/命令/网络）
  + workspace-write 沙箱
  + Defender 受控文件夹
```

四层各管一段，任何一层单独都不够。

## 测试

```bash
cd dsh-write-guard
node --test
```

**单元测试**覆盖命令参数与注释中的假目标、内联脚本后的真实重定向、预演与规则加载失败，以及：正常放行、脚本转人工、下载执行/持久化/凭证/反弹 Shell、进程替换与 `eval` 下载执行、双扩展名、Win32 尾点、二进制、全角/零宽/西里尔混淆、文档降级与自定义规则不被降级、PE/ELF/ZIP 文件头、归档、硬上限、UTF-8 截断、熵检测、shell heredoc（两种顺序、数据正文遮罩、脚本正文递归、非 shell 正文转人工）/PowerShell here-string（正文遮罩、管道给 shell 递归、未闭合）/echo/printf/tee/Tee-Object/Set-Content/Add-Content/Out-File/Set-Item/WriteAllText/New-Item/下载（含 `irm`、certutil、bitsadmin）/解压默认目录/引号感知重定向/动态路径、PowerShell 参数任意顺序与非字面量值、自定义规则编译与 ReDoS 拒绝、哈希链、自校验基线/篡改/版本升级、python -c/node -e 内联代码、写后校验/篡改/缺失/超限/UTF-16 解码、配置默认值。

集成冒烟测试真实 mount 插件并调用两个 waterfall：

```bash
node scripts/smoke.mjs
```

**冒烟断言**覆盖根目录与子目录同名文件、条件写入是否实际落盘，以及：工具注册、恶意 PowerShell 拒绝、`.exe` 拒绝、`edit` 只看替换内容、shell 重定向载荷拒绝、低风险重定向放行、`tee` 转人工、动态路径转人工且不进入写后校验、`mode=off` 完全放行、写后哈希一致接受、篡改拒绝、无 `callId` 拒绝、已批准脚本放行、工具失败且未写入不误报、失败但已写入仍扫描、缺失文件阻断、Shell 目标缺失阻断、Shell 写后重扫、超单次扫描上限的完整文件检测、只读工具按会话 cwd 加载项目规则。

## License

MIT
