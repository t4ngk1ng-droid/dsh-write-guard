# dsh-write-guard 中文介绍

## 一句话

**它帮你判断：Agent 准备写进文件的内容，值不值得先停下来确认。** 比如，同样叫 `setup.ps1`，有的只是设置环境变量，有的却会从网上下载代码并立即运行。DeepSeek Harness 的路径权限不能只凭文件名区分两者；这个插件会看内容，写完后再核对文件。

---

## 它解决什么真实问题

路径规则和命令白名单回答的是“能写哪里”和“能运行什么”。如果 Agent 已经获准在工作区写文件，文件内容仍需要另一道检查。

例如，你让 Agent 帮忙改一个安装脚本：

```
你：帮我从那个仓库拉个安装脚本，修一下 Windows 兼容
Agent：（从 README 里抄了一段带 IEX DownloadString 的 PowerShell，存成 setup.ps1）
你：（双击运行）
```

脚本保存在允许的工作区内，Agent 当时只写了文件，并没有执行脚本。问题要等你双击时才显现：文件里的代码会联网下载并运行其他内容。

dsh-write-guard 把检查提前到写入时。它不需要先判断 README 里那句话是不是提示注入，而是看这次写入是否出现了需要确认的特征。

---

## 它怎么工作

插件在 DSH 的两个时点工作：

| 时机 | 做什么 |
|---|---|
| **落盘前**（`tools/pre-execute`） | 扫描新增内容，寻找下载即执行、混淆、凭证窃取、持久化、反弹 Shell、PE/ELF 文件头、双扩展名、高熵串等特征。对于 `bash`/`pwsh`，还识别重定向、heredoc、`Set-Content`、`Out-File`、`tee`、下载和解压等常见写法 |
| **落盘后**（`tools/post-execute`） | 读回能定位、未超读取上限的目标并重扫全文；直接 `write` 还核对批准内容的哈希。即使每次编辑都很小，拼起来才出现的特征也有机会在这一步被发现 |

判定分三档：

- **allow**：放行
- **ask**：暂缓执行，交给 DSH 的审批链确认。它表示需要复核，不等于文件已被判定为恶意。
- **deny**：拒绝本次写入；开启隔离时，保留可取得的被拒内容供复核。

同一次调用涉及多项判定时，最严格的一档生效。默认把决策写入带哈希链的审计日志。写后报告 `block` 时，文件可能已经在磁盘上，插件不会把它恢复到旧版本。

---

## 和别的防护是什么关系

它和现有防护检查的是不同问题：

```
write-guard（内容 + shell + 写后校验）
  + 权限规则（路径 / 命令 / 网络）
  + 工作区沙箱
  + Windows Defender
```

路径权限决定“能不能写到这儿”，工作区沙箱限制可触及的范围，Windows Defender 检查系统中的威胁。这个插件看的是一次 Agent 写入的内容和结果。

它**不是杀毒软件**，也不识别所有提示注入。它用启发式规则提示或拒绝常见的危险写入，并留下复核记录；放行不证明文件安全。

---

## 怎么用

安装方法见 [README 的安装步骤](README.md#安装)。默认采用 `enforce`：该确认的写入会进入审批，该拒绝的会被拦下。

```yaml
- id: write-guard
  config:
    mode: enforce       # enforce | dry-run | off
```

如果不确定现有项目会触发哪些规则，可先用 `dry-run` 跑一两天。本插件只记录“本来会拦什么”，不执行拦截；看过日志后再切回 `enforce`。

### 在 DSH 设置里改

打开 **DSH 设置 → 写入防护**。面板有模式选择、9 类 Shell 检测、14 类内容检测和 13 个其他开关。修改后点「保存」；是否需要重启取决于改的是哪一项。

### 也可以对 Agent 说一句

不用打开设置页：

> 「把解压检测关掉」
> 「列出 write-guard 现在哪些开关是关的」
> 「切成 dry-run 跑两天」

Agent 会调用 `write_guard_config`。改动保存在 `<DSH_HOME>/write-guard/config.json`，优先于 profile。想重新跟随 profile，请清除对应的运行时覆盖；只有 profile 也没设时，才会回到插件的出厂默认。`dry-run` 是全局模式，不会在两天后自动切回。

大多数检测开关保存后即可生效，包括 `quarantine`。`audit`、`notify`、`integrity` 改动后要重启。还有一些非面板参数也是启动时读取，例如写后校验的大小上限。

按类别开关（`shellChecks`）可以关掉某一类检测：

```yaml
    shellChecks:
      download: true    # 下载到文件
      extract: true     # 解压
      tee: true
      cmdlets: true     # Set-Content / Out-File / New-Item
      copy: true        # cp / mv / Copy-Item / dd of=
      redirect: true    # > / >>
      echo: true
      heredoc: true
      dotnet: true
```

设为 `false` 表示**这一类不再上报**，不是改为“只记录”；同一命令里的其他写入仍可能触发检查。先从日志里确认是哪一类产生误报，再决定要不要关。

内容扫描同样按类别开关（`contentChecks`），14 类：

```yaml
    contentChecks:
      download-execute: true      # 下载即执行
      encoded-payload: true       # 编码载荷、高熵串
      obfuscation: true           # 混淆
      persistence: true           # 持久化
      credential-theft: true      # 凭证窃取
      reverse-shell: true         # 反弹 Shell
      defense-evasion: true       # 防御规避
      privilege-escalation: true  # 提权
      office-macro: true          # Office 宏
      archive: true               # 解压后执行
      propagation: true           # 传播
      magic: true                 # PE/ELF/ZIP 文件头
      binary: true                # 二进制控制字节
      double-extension: true      # invoice.pdf.exe
```

除此之外还有一组整功能开关，常用的几个：

| 开关 | 关掉之后 |
|---|---|
| `shellGuard: false` | 完全不解析 shell 写入 |
| `verifyWrites: false` | 不再读回文件，失去通过完整文件重扫发现分片拼接的机会 |
| `entropy: false` | 不检测高熵编码串 |
| `homoglyph: false` | 关闭西里尔/希腊相似字母映射；全角规范化与零宽字符清理仍保留 |
| `blockBinaries: false` | 写可执行后缀从"拒绝"降为"确认" |
| `docPolicy: enforce` | 文档中的命令示例不再因文档类型降级，按正常分数判定 |
| `quarantine: false` | 被拒的载荷不留证 |
| `audit: false` | 不写审计日志（拒绝原因仍会返回） |
| `integrity: false` | 不校验插件自身文件是否被改 |

`contentChecks` 控制内置检测类别，不会关掉来自 `write-guard.rules.json` 的项目 `custom` 规则。

---

## 默认策略

| 场景 | 默认行为 |
|---|---|
| 未命中特征的普通代码、文档 | 放行 |
| 裸脚本（`.ps1`/`.bat`/`.cmd`/`.sh`） | 转人工 |
| 下载、解压、管道写入 | 转人工（内容无法静态检查） |
| 命中高危特征 | 拒绝 + 隔离 |
| 写后哈希不符 | 阻断并说明"文件已落盘、未自动回滚" |

---

## 它明确做不到什么

下面这些情况不能只靠这个插件判断：

1. **不是所有危险内容都有已知特征。** 强混淆、新变种和分片写入可能不被发现。完整文件重扫能补上一部分，不能证明安全。
2. **Shell 解析不是完整解释器。** 常见的 `cp`/`mv`/`dd of=` 可以识别目标，但不代表复制内容已在写前检查，也不保证覆盖所有参数组合。`sed -i`、`ssh`/`mysql` 的 heredoc 等仍不在相同覆盖范围内。
3. **不分析解释器内联代码。** `python -c`、`node -e` 正文中的文件操作不可见；正文之后的 Shell 重定向是另一回事。
4. **不主动扫描磁盘上的已有文件。** 检查范围是 Agent 准备写入的内容，以及这次操作后能够读回的目标。
5. **审计链没有外部信任锚。** 它可帮助识别日志中间的改动，但不能证明末尾的记录没有被截断。
6. **`ask` 的最终决定在 DSH 审批链。** 由人还是第二个模型回答，取决于你的审批配置。

完整清单见 README 的「局限」一节。

---

## 适合谁

- 用 DSH 桌面版、让 Agent 长期在本地干活，会经常写脚本/装依赖的人
- 担心"Agent 从网上抄了一段东西直接写进文件"这类事故的人
- 想要一份可追溯的写入审计，而不只是"拦截/放行"两态的人

如果要持续监控整台机器、调查已执行程序，或应对专门规避检测的攻击者，需要的是 EDR 等系统防护工具，不是这个插件。

---

## 仓库

https://github.com/t4ngk1ng-droid/dsh-write-guard

MIT License。零运行时依赖，纯 Node 内置模块。
