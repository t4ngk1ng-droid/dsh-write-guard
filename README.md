# dsh-write-guard

**DeepSeek Harness 的文件写入防护插件。** 路径规则可以允许 Agent 写 `setup.ps1`，却无法区分普通安装步骤和下载后立即执行的代码。dsh-write-guard 在写入前检查内容，在写入后读回可定位的文件，核对实际落盘结果。

适用于会让 Agent 改代码、写脚本或运行 Shell 的 DSH 用户。插件使用 Node.js 内置模块，要求 Node.js >= 20.0.0，零运行时依赖。**[安装](#安装)**：`dsh plugin add dsh-write-guard`，或从仓库安装。初次试用建议先开 `dry-run`。

> 它检查的是提示注入或误操作可能造成的**文件写入后果**，不判断提示词是否恶意，也不替代杀毒软件。写后阻断不会自动回滚文件。

**只想了解它会拦什么？** 看[中文介绍](GUIDE-zh.md)，其中列出了默认策略、遇到确认时该怎么看，以及它做不到什么。

## 为什么需要它

风险不一定出现在 Agent 执行命令的时候。Agent 也可能先把不可信的内容写成文件，之后再由用户、计划任务或其他程序运行：

```
用户: 帮我从那个仓库拉个安装脚本，修一下 Windows 兼容
Agent: （从 README 里抄一段带 IEX DownloadString 的 PowerShell，写进 setup.ps1）
用户: （双击运行）
```

这里写的是工作区里的普通脚本，工具调用也不是 `bash -c`。如果权限规则允许这次写入，仅凭路径就无法解释为什么需要复核；内容检查可以指出脚本中的下载执行行为。

## 能力

| 层面 | 检查 |
|---|---|
| 文件写入 | 在 `tools/pre-execute` 检查 `write` / `edit` / `str_replace_editor` 的目标路径和即将写入的内容；编辑时先看新增或替换的部分 |
| Shell 写入 | heredoc（两种顺序）、`echo/printf >`、`Set-Content`、`Add-Content`、`Out-File`、`Set-Item`、`[IO.File]::WriteAllText`、`New-Item -Value` |
| Shell 未知写入 | 识别 `curl -o`、`wget -O`、`Invoke-WebRequest`/`Invoke-RestMethod -OutFile`、certutil/bitsadmin、`Expand-Archive`/`tar -x`/`unzip`/`7z x`（含默认当前目录）、`tee`/`Tee-Object`、无 `-Value` 的 `Out-File` 及通用 `>` 重定向。也识别 `cp`/`mv`/`dd of=`、`Copy-Item` 等常见目标；拿不到内容时，按来源和目标类型决定是否转审批 |
| 路径 | 可执行扩展名（`.exe/.dll/.scr/.vbs/.hta/.jar/.xll`…）、双扩展名（`invoice.pdf.exe`）、Win32 尾点/尾空格、脚本扩展名 |
| 内容 | 27 条内置规则：下载即执行、编码载荷、混淆、持久化、凭证窃取、反弹 Shell、AV 篡改、UAC 绕过、Office 宏、归档解压执行、传播 |
| 文件头 | PE / ELF / Mach-O / ZIP / RAR / 7z / GZIP magic；可执行头写进文本文件直接拒绝 |
| 编码折叠 | NFKC + 零宽/双向控制字符剥离 + 西里尔/希腊字母混淆映射 |
| 熵 | 标记长 base64/hex 高熵串，作为可能含压缩或加密数据的线索，不单凭编码断定恶意 |
| 分片 | 在写后读取上限内重扫完整文件，以发现多次编辑拼接后才出现的特征 |
| 哈希 | 对可直接比对的 `write`，核对批准内容与落盘内容的哈希。不同表示结果不一致，不单凭哈希判定是谁改了文件 |
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

写前按 `deny > ask > allow` 合并；`ask` 交给 DSH 审批链。写后检查的是已经发生的写入：`write` 可核对批准内容的哈希，编辑和 Shell 写入主要靠全文重扫。默认 `block` 会把校验失败或风险升级反馈给模型，不会撤销写入。

## 安装

**Web profile：** 从 npm 安装：

```bash
dsh plugin --profile web add dsh-write-guard
```

或从仓库安装（想跟最新提交时）：

```bash
git clone https://github.com/t4ngk1ng-droid/dsh-write-guard.git
dsh plugin --profile web add file:./dsh-write-guard
```

Windows 上的 `add` 依赖 pnpm；还没有 pnpm 时，先运行 `corepack enable pnpm`。

**桌面版：** `desktop` profile 由 Electron 独占，不能用上面的 CLI 命令直接写入。按以下步骤手动安装：

1. 在克隆的仓库目录运行 `npm pack` 生成 tgz，或准备直接复制仓库目录。
2. 将包内容解压或复制到 `~/.dsh/profiles/desktop/node_modules/dsh-write-guard`，确认 `package.json` 就在该目录下，而不是再嵌套一层。
3. 在 `~/.dsh/profiles/desktop/package.json` 的 `dependencies` 中添加 `"dsh-write-guard": "file:../../plugins/dsh-write-guard"`，并将 `dsh-write-guard` 加入 `dsh.profile.bundles`。该 `file:` 示例要求 `~/.dsh/plugins/dsh-write-guard` 也有对应插件源码；若克隆在别处，依赖路径要指向实际位置。
4. 在 `cordis.patch.yml` 里设 `- id: write-guard` + `config.mode: dry-run`，重启 DSH；看过审计结果后再切 `enforce`。

首次运行会在 `~/.dsh/write-guard/` 建立完整性基线。**升级后看到 `tampered`，先核对新版本及文件来源。** 只有确认是预期更新时，才删除该目录下的 `integrity.json` 并重启，以新版本重建基线。

## 配置

以下是 `cordis.patch.yml` 的常用项，均可省略。profile 给出基础策略；设置面板或对话工具保存的运行时覆盖优先。

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
          copy: true               # cp、mv、Copy-Item、Move-Item、dd of=
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

**常用开关一览**

| 开关 | 默认 | 改动后的效果 |
|---|---|---|
| `mode` | `enforce` | `dry-run` 只记录不拦；`off` 完全关闭 |
| `blockThreshold` / `askThreshold` | 70 / 40 | 调整判定分界 |
| `shellGuard` | true | 完全不解析 shell 写入 |
| `shellChecks.*`（9 类） | true | 关闭某类后，该类不再上报；同一命令中的其他写入仍单独检查 |
| `shellUnknownPolicy` | `ask` | `allow`：内容不可检查的写入直接放行 |
| `verifyWrites` | true | 不做写后校验 |
| `verifyPolicy` | `block` | `audit`：哈希不符、无法完成校验或重扫升级时只记录，不由此阻断 |
| `contentChecks.*`（14 类） | true | 该类内容检测不再扫描 |
| `entropy` | true | 不做高熵串检测 |
| `homoglyph` | true | 关闭西里尔/希腊相似字母映射；全角规范化和零宽字符清理仍保留 |
| `blockBinaries` | true | 写可执行扩展名降为 `ask` |
| `scriptPolicy` | `ask` | `allow` / `deny` 裸脚本 |
| `docPolicy` | `downgrade` | `enforce`：文档里的命令示例同样拦截 |
| `quarantine` | true | 被拒载荷不留存 |
| `audit` / `auditHashChain` | true | 不写审计 / 不加哈希链 |
| `integrity` | true | 不做插件自身指纹校验 |
| `notify` | false | 告警通道 |
| `onScannerError` | `ask` | `allow`：不因本次扫描异常要求确认；同一调用已得出的更严判定仍保留 |

**首次试用：** `mode: dry-run` 只记录“本来会拦什么”，不执行拦截。跑一两天，核对审计日志里是否有误报，再切换为 `enforce`。

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

- `probe`：可选的预筛子串；至少命中一个才检查该规则的模式。
- `paths`：可选的路径 glob；只对匹配的目标应用规则。
- `severity`：1-100，按全局阈值参与判定。
- 自定义规则不享受文档降级：如果某条规则的分数足以 `deny`，写入 `.md` 也不会因此改判 `ask`。
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

### 在设置页改开关

打开 **DSH 设置 → 写入防护**，选好类别后点「保存」。多数开关即时生效；`audit`、`notify`、`integrity` 等需要重启。`quarantine` 开关即时生效，隔离目录则在装载时确定。

面板通过 `/dsh-write-guard/config` 保存与上次读取值的差异。它和对话工具写同一份覆盖文件，不是两套独立策略。

### 在对话里改开关

不用编辑 YAML。直接对 Agent 说：

> 「把解压检测关掉」
> 「列出 write-guard 现在哪些开关是关的」
> 「下载检测改成只记录不拦」

Agent 通过 `write_guard_config` 把允许修改的字段写入 `<DSH_HOME>/write-guard/config.json`。注意最后一个例子的范围：下载类别本身只有开和关；`dry-run` 是**全局**只记录模式，不是单类别模式。

也可以自己指定参数：

```json
{ "set": { "shellChecks": { "extract": false } } }
{ "set": { "mode": "dry-run" } }
{ "clear": ["shellChecks"] }        // 恢复默认
```

`shellChecks` 按子键合并：只写 `{ "shellChecks": { "extract": false } }`，其余 8 类继续沿用各自设置。上例中的“恢复默认”指清除该组**运行时覆盖**，回到 profile；profile 未指定的值才回到出厂默认。

**保存不等于已经生效。** `audit`、`auditHashChain`、`notify`、`notifyMinScore`、`integrity` 和 `maxVerifyBytes` 在装载时确定，改动后需要重启。`quarantine` 开关即时生效；`notifyCommand` 等命令或路径字段请在 profile 中维护。

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

审计日志超过 5 MB 自动轮转。`write_guard_verify_chain` 检查单个日志段内各条记录的链接，能报告中间断链。没有外部保存的可信链头，就不能证明尾部未被截断。

通知：设 `notify: true` 并配 `notifyCommand`，消息通过环境变量 `WG_MESSAGE` 传入，不会拼进命令行。例如（PowerShell + BurntToast）：

```yaml
notify: true
notifyCommand: powershell -NoProfile -Command "New-BurntToastNotification -Text $env:WG_MESSAGE"
```

## 自校验

插件启动时，对自身文件（`index.js`、`lib/`、随包提供的脚本、测试、配置与文档）计算 sha256，与 `~/.dsh/write-guard/integrity.json` 比对。首次运行建立基线；文件或版本变化会报告 `tampered`，不会因为版本号更新就自动信任新内容。正常升级的基线重建步骤见[安装](#安装)。

这是**变更证据，不是防篡改机制**。默认 `workspace-write` 沙箱里的 Agent 不能写 `~/.dsh` 的基线；如果某个进程同时能改插件和基线，二者就不能互相证明可信。

## 局限（重要）

1. **启发式，不是签名引擎。** 新变种、强混淆、分片写入都能绕过。二次扫描补上了"写完才看得出"的那一类，但不能证明安全。
2. **Shell 解析不是完整解释器。** 它能识别 `cp`/`mv`、`dd of=` 等常见写入目标，不代表能还原复制的内容或每种参数组合。变量、命令替换和 glob 目标按动态写入处理，默认转审批。`python -c`/`node -e` 内的 `open(...)`、`awk`/`sed -i` 以及深层嵌套的 `bash -c` 仍无法静态还原。heredoc 的数据正文不会被当作命令；`bash <<EOF` / `cat <<EOF | bash` 的脚本正文会递归解析，`python`/`node` 等非 Shell 解释器的 heredoc 正文转审批。未闭合或动态 delimiter 仍可能被误读。
3. **不扫描磁盘上已有的文件。** 只管"这次要写什么"和"刚写完的是什么"；已落盘的二进制请用 Windows Defender 或 `dsh-secure-audit`。
4. **`ask` 之后由审批链决定。** 配了 `dsh-auto-review` 是第二个模型在答，否则是你本人。
5. **超限只扫前缀。** `truncatePolicy: allow` 会明确承担未扫描后缀的风险。
6. **成功执行不等于每个分支都写了文件。** `verifyPolicy: block` 下，普通写入缺失仍阻断。对于 Bash 中能静态判断的短路（如 `test -d . || …`），仅宽免未执行分支的 `ENOENT`；已有目标仍重扫，不能判定的分支仍须校验。`cd sub && …` 中的相对目标按 `sub` 校验；目录依赖变量或条件合流而不能确定时，按动态目标策略处理，不猜测落盘位置。PowerShell 内置 cmdlet 明确生效的 `-WhatIf` 和非文件 `Env:` 写入不登记为文件，外层重定向仍单独检查。
7. **写后校验有读取上限。** 目标超过 `maxVerifyBytes`（默认 8 MB）时不会被当作已验证。在 `verifyPolicy: block` 下这会阻断后续；如果经常写更大的文件，可调高上限并重启，或明确选择只记录的 `audit` 策略。

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

当前 **266 个单元测试**，全部通过。

**单元测试**覆盖设置路由（信任检查失败即拒绝、413/400、原型污染、只保存 diff、面板与配置字段一致性），以及三条写入路径：

- 内容扫描：正常写入、下载执行/持久化/凭证/反弹 Shell、进程替换与 `eval` 下载执行、双扩展名、Win32 尾点、二进制与 PE/ELF/ZIP 文件头、归档、高熵串、全角/零宽/西里尔混淆、文档降级和自定义规则。
- Shell 提取：heredoc（两种顺序、数据正文、递归脚本和非 Shell 解释器）、PowerShell here-string（含未闭合）、echo/printf/tee/Tee-Object/Set-Content/Add-Content/Out-File/Set-Item/WriteAllText/New-Item、下载（含 `irm`、certutil、bitsadmin）、解压默认目录、内联脚本后的真实重定向、动态路径、PowerShell 参数顺序和表达式、预演与只读命令的假目标。
- 校验和配置：写后篡改/缺失/超限、UTF-16 解码、UTF-8 截断和硬上限、规则加载失败与 ReDoS 拒绝、审计哈希链、完整性基线和版本升级、`python -c`/`node -e` 的参数边界及配置默认值。

集成冒烟测试在模拟 DSH 宿主中装载真实插件，调用写前和写后两个钩子：

```bash
node scripts/smoke.mjs
```

**冒烟断言**检查工具注册、普通写入是否放行、恶意 PowerShell 和 `.exe` 是否拒绝、`edit` 是否只看替换内容，以及 `tee`、动态路径和 `mode=off` 的行为。写后对照包括：根目录和子目录同名文件、条件分支、缺少 `callId`、哈希相符或不符、审批后的脚本、工具失败但文件已写入、目标缺失、Shell 写后重扫、超过单次扫描上限的全文检测，以及按会话 cwd 加载项目规则。

## License

MIT
