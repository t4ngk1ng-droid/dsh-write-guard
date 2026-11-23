/**
 * dsh-write-guard — 浏览器半侧（设置页「写入防护」）
 * ----------------------------------------------------------------------------
 * 以 dsh.client bundle 格式加载（手写 ModuleLoader bundle，无需构建）。
 * 在 DSH 设置里注册一个 `settings.section`，用来改 write-guard 的全部开关。
 *
 * 数据不走 settings 命名空间，而是走 Host 半侧的 HTTP API
 * （GET/POST /dsh-write-guard/config），与 dsh-startup-screen 同款做法。
 * 注册 id 必须等于 loader entry 名（write-guard），否则 ModuleLoader 会报
 * "loaded without registering write-guard"。
 *
 * 没有 webServer 的 profile（Electron 走 file:// + IPC）拿不到这个端点，
 * 面板会显示错误提示；那种情况下用对话里的 write_guard_config 工具，
 * 或直接改 cordis.patch.yml。
 */
/*
 * The `typeof window` guard is required: the host imports this module to read
 * its metadata, and touching `window` there throws.
 *
 * There is deliberately no registration flag. client-modules skips a row that
 * is already registered or cached, so a replay is handled on its side. The
 * bundle id must equal the loader entry's *name* (the package name) — that is
 * what client-modules matches the registration against.
 */
if (
  typeof window !== 'undefined' &&
  window.__ModuleLoader__ &&
  typeof window.__ModuleLoader__.load === 'function'
) {
  window.__ModuleLoader__.load({
  id: 'dsh-write-guard',
  factory: (require) => {
    var module = { exports: {} }
    var exports = module.exports
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' })

    var react = require('react')
    var h = react.createElement

    var API = '/dsh-write-guard/config'

    /* ── 字段表 ──────────────────────────────────────────────────────────── */

    var MODES = [
      { value: 'enforce', label: 'enforce — 拦截' },
      { value: 'dry-run', label: 'dry-run — 只记录' },
      { value: 'off', label: 'off — 完全关闭' },
    ]

    var SHELL_CHECKS = [
      ['redirect', '重定向', '> / >> / &> 写入文件'],
      ['echo', 'echo / printf', '把内容写进文件'],
      ['heredoc', 'heredoc', 'heredoc 与 stdin 脚本正文'],
      ['tee', 'tee', 'tee / Tee-Object'],
      ['download', '下载', 'curl -o、iwr/irm -OutFile、certutil、bitsadmin'],
      ['extract', '解压', 'tar / unzip / 7z / Expand-Archive'],
      ['dotnet', '.NET 写文件', '[IO.File]::WriteAllText 等'],
      ['cmdlets', 'PowerShell cmdlet', 'Set-Content、Out-File、New-Item、Start-Process'],
    ]

    var CONTENT_CHECKS = [
      ['download-execute', '下载即执行', '下载到内存再运行'],
      ['encoded-payload', '编码载荷', 'base64/hex、高熵串'],
      ['obfuscation', '混淆', '字符串拼接、超长单行'],
      ['persistence', '持久化', 'Run 键、计划任务、服务'],
      ['credential-theft', '凭证窃取', '浏览器库、token、键盘记录'],
      ['reverse-shell', '反弹 Shell', 'nc / socat / 套接字'],
      ['defense-evasion', '防御规避', '改 AMSI/Defender、关日志'],
      ['privilege-escalation', '提权', 'UAC 绕过'],
      ['office-macro', 'Office 宏', 'VBA 自动执行、DDE'],
      ['archive', '归档执行', '解压后运行'],
      ['propagation', '传播', '拷贝到共享/USB、自传播'],
      ['magic', '文件头', 'PE/ELF/Mach-O/ZIP'],
      ['binary', '二进制内容', 'NUL 与控制字节'],
      ['double-extension', '双扩展名', 'invoice.pdf.exe'],
    ]

    var SWITCHES = [
      ['scriptPolicy', '裸脚本', [['ask', '转人工'], ['allow', '放行'], ['deny', '拒绝']]],
      ['docPolicy', '文档里的命令示例', [['downgrade', '降级'], ['enforce', '照常拦截']]],
      ['verifyPolicy', '写后哈希不符', [['block', '阻断'], ['audit', '只记录']]],
      ['shellUnknownPolicy', '内容不可检查的 shell 写入', [['ask', '转人工'], ['allow', '放行']]],
      ['blockBinaries', '写可执行后缀', null],
      ['verifyWrites', '写后校验', null],
      ['entropy', '高熵串检测', null],
      ['homoglyph', '全角/零宽/西里尔折叠', null],
      ['shellGuard', '解析 shell 写入', null],
      ['quarantine', '隔离被拒载荷', 'restart'],
      ['audit', '写审计日志', 'restart'],
      ['integrity', '插件自校验', 'restart'],
      ['notify', '告警通知', 'restart'],
    ]

    /* ── 样式 ────────────────────────────────────────────────────────────── */

    var CSS = [
      '.__wg_root{max-width:620px;display:flex;flex-direction:column;gap:12px;font-size:13px;color:var(--dsw-alias-label-primary)}',
      '.__wg_head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}',
      '.__wg_ver{font-family:ui-monospace,Consolas,monospace;font-size:12px;letter-spacing:.04em;color:var(--dsw-alias-label-tertiary)}',
      '.__wg_group{border:1px solid var(--dsw-alias-border-l2);border-radius:10px;padding:12px 14px;display:flex;flex-direction:column;gap:9px}',
      '.__wg_title{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--dsw-alias-label-tertiary)}',
      '.__wg_row{display:flex;align-items:flex-start;gap:8px}',
      '.__wg_row input[type=checkbox]{margin-top:3px;accent-color:var(--dsw-alias-state-business-primary)}',
      '.__wg_text{display:flex;flex-direction:column;gap:1px}',
      '.__wg_name{font-size:12.5px;font-weight:600}',
      '.__wg_hint{font-size:11px;line-height:1.5;color:var(--dsw-alias-label-tertiary)}',
      '.__wg_off .__wg_name{opacity:.55;font-weight:500}',
      '.__wg_select{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:5px 8px;font:inherit;font-size:12.5px;min-width:200px}',
      '.__wg_line{display:flex;align-items:center;gap:10px;flex-wrap:wrap}',
      '.__wg_label{font-size:12px;font-weight:600;min-width:150px}',
      '.__wg_actions{position:sticky;bottom:-2px;z-index:3;display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:9px 0 7px;background:var(--dsw-alias-bg-layer-1,transparent);border-top:1px solid var(--dsw-alias-border-l2)}',
      '.__wg_btn{border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-3);color:var(--dsw-alias-label-primary);border-radius:8px;padding:6px 14px;font:inherit;font-size:13px;cursor:pointer}',
      '.__wg_btn:hover:not(:disabled){border-color:var(--dsw-alias-state-business-primary)}',
      '.__wg_btn:disabled{opacity:.5;cursor:default}',
      '.__wg_primary{border-color:var(--dsw-alias-state-business-primary,#3964fe);background:var(--dsw-alias-state-business-primary,#3964fe);color:#fff}',
      '.__wg_note{font-size:11.5px;color:var(--dsw-alias-label-tertiary)}',
      '.__wg_ok{font-size:12px;color:var(--dsw-alias-state-business-primary)}',
      '.__wg_err{font-size:12px;color:var(--dsw-alias-state-error-primary,#f85149)}',
      '.__wg_dirty{font-size:12px;font-weight:600;color:var(--dsw-alias-state-warning-primary,#c26a00)}',
    ]

    var STYLE_ID = 'dsh-write-guard-settings-css'

    function ensureCss() {
      try {
        if (document.getElementById(STYLE_ID)) return
        var style = document.createElement('style')
        style.id = STYLE_ID
        style.textContent = CSS.join('\n')
        document.head.appendChild(style)
      } catch (e) {
        /* 样式失败不影响功能 */
      }
    }

    /* ── 面板 ────────────────────────────────────────────────────────────── */

    function Row(props) {
      return h(
        'label',
        { className: '__wg_row ' + (props.on ? '' : '__wg_off') },
        h('input', {
          type: 'checkbox',
          checked: !!props.on,
          onChange: (e) => props.onChange(e.target.checked),
        }),
        h(
          'span',
          { className: '__wg_text' },
          h('span', { className: '__wg_name' }, props.name),
          props.hint ? h('span', { className: '__wg_hint' }, props.hint) : null,
        ),
      )
    }

    function Panel() {
      var [draft, setDraft] = react.useState(null)
      var [error, setError] = react.useState(null)
      var [notice, setNotice] = react.useState(null)
      var [busy, setBusy] = react.useState(false)
      var [file, setFile] = react.useState('')
      var [restartOnly, setRestartOnly] = react.useState([])
      var [dirty, setDirty] = react.useState(false)

      function load() {
        setError(null)
        return fetch(API, { headers: { Accept: 'application/json' } })
          .then((r) => r.json())
          .then((j) => {
            if (!j || j.ok !== true) throw new Error((j && j.error) || 'load failed')
            setDraft(j.config)
            setFile(j.file || '')
            setRestartOnly(Array.isArray(j.restartOnly) ? j.restartOnly : [])
            setDirty(false)
          })
          .catch((e) => setError('读取配置失败：' + String((e && e.message) || e) + '（这个环境可能没有设置端点，改用对话里的 write_guard_config）'))
      }

      react.useEffect(() => {
        ensureCss()
        load()
      }, [])

      function patch(fn) {
        setDraft((prev) => {
          var next = JSON.parse(JSON.stringify(prev))
          fn(next)
          return next
        })
        setDirty(true)
        setNotice(null)
      }

      function save() {
        if (!draft) return
        setBusy(true)
        setError(null)
        setNotice(null)
        fetch(API, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            set: {
              mode: draft.mode,
              scriptPolicy: draft.scriptPolicy,
              docPolicy: draft.docPolicy,
              verifyPolicy: draft.verifyPolicy,
              shellUnknownPolicy: draft.shellUnknownPolicy,
              blockBinaries: draft.blockBinaries,
              verifyWrites: draft.verifyWrites,
              entropy: draft.entropy,
              homoglyph: draft.homoglyph,
              shellGuard: draft.shellGuard,
              quarantine: draft.quarantine,
              audit: draft.audit,
              integrity: draft.integrity,
              notify: draft.notify,
              shellChecks: draft.shellChecks,
              contentChecks: draft.contentChecks,
            },
          }),
        })
          .then((r) => r.json())
          .then((j) => {
            if (!j || j.ok !== true) throw new Error((j && j.error) || 'save failed')
            setDraft(j.config)
            setDirty(false)
            setNotice('已保存并生效' + (restartOnly.length ? '（标记「需重启」的项重启后生效）' : ''))
          })
          .catch((e) => setError('保存失败：' + String((e && e.message) || e)))
          .finally(() => setBusy(false))
      }

      function reset() {
        setBusy(true)
        fetch(API, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ clear: ['mode', 'shellChecks', 'contentChecks', 'scriptPolicy', 'docPolicy', 'verifyPolicy', 'shellUnknownPolicy', 'blockBinaries', 'verifyWrites', 'entropy', 'homoglyph', 'shellGuard', 'quarantine', 'audit', 'integrity', 'notify'] }),
        })
          .then((r) => r.json())
          .then((j) => {
            if (!j || j.ok !== true) throw new Error((j && j.error) || 'reset failed')
            setDraft(j.config)
            setDirty(false)
            setNotice('已恢复默认')
          })
          .catch((e) => setError('恢复默认失败：' + String((e && e.message) || e)))
          .finally(() => setBusy(false))
      }

      if (error && !draft) {
        return h('div', { className: '__wg_root' }, h('div', { className: '__wg_err' }, error))
      }
      if (!draft) return h('div', { className: '__wg_root' }, h('div', { className: '__wg_note' }, '读取中…'))

      var restart = (key) => restartOnly.indexOf(key) >= 0

      return h(
        'div',
        { className: '__wg_root' },
        h(
          'div',
          { className: '__wg_head' },
          h('span', { className: '__wg_ver' }, 'dsh-write-guard'),
          dirty ? h('span', { className: '__wg_dirty' }, '有未保存的改动') : null,
        ),

        h(
          'div',
          { className: '__wg_group' },
          h('span', { className: '__wg_title' }, '判定模式'),
          h(
            'div',
            { className: '__wg_line' },
            h('span', { className: '__wg_label' }, '模式'),
            h(
              'select',
              {
                className: '__wg_select',
                value: draft.mode,
                onChange: (e) => patch((d) => { d.mode = e.target.value }),
              },
              MODES.map((m) => h('option', { key: m.value, value: m.value }, m.label)),
            ),
          ),
          h('span', { className: '__wg_hint' }, 'dry-run 只记录「本来会拦什么」，不实际拦截。'),
        ),

        h(
          'div',
          { className: '__wg_group' },
          h('span', { className: '__wg_title' }, 'Shell 写入检测'),
          SHELL_CHECKS.map(([key, name, hint]) =>
            h(Row, {
              key,
              name,
              hint,
              on: draft.shellChecks[key] !== false,
              onChange: (on) => patch((d) => { d.shellChecks[key] = on }),
            }),
          ),
        ),

        h(
          'div',
          { className: '__wg_group' },
          h('span', { className: '__wg_title' }, '内容检测'),
          CONTENT_CHECKS.map(([key, name, hint]) =>
            h(Row, {
              key,
              name,
              hint,
              on: draft.contentChecks[key] !== false,
              onChange: (on) => patch((d) => { d.contentChecks[key] = on }),
            }),
          ),
        ),

        h(
          'div',
          { className: '__wg_group' },
          h('span', { className: '__wg_title' }, '其他'),
          SWITCHES.map(([key, name, options]) => {
            if (Array.isArray(options)) {
              return h(
                'div',
                { className: '__wg_line', key },
                h('span', { className: '__wg_label' }, name),
                h(
                  'select',
                  {
                    className: '__wg_select',
                    value: draft[key],
                    onChange: (e) => patch((d) => { d[key] = e.target.value }),
                  },
                  options.map(([value, label]) => h('option', { key: value, value }, label)),
                ),
              )
            }
            return h(
              'div',
              { key },
              h(Row, {
                name: name + (options === 'restart' ? '（需重启）' : ''),
                on: draft[key] !== false,
                onChange: (on) => patch((d) => { d[key] = on }),
              }),
            )
          }),
        ),

        h(
          'div',
          { className: '__wg_actions' },
          h(
            'button',
            { className: '__wg_btn __wg_primary', disabled: busy || !dirty, onClick: save },
            busy ? '保存中…' : '保存',
          ),
          h('button', { className: '__wg_btn', disabled: busy, onClick: reset }, '恢复默认'),
          h('button', { className: '__wg_btn', disabled: busy, onClick: load }, '重新读取'),
          notice ? h('span', { className: '__wg_ok' }, notice) : null,
          error ? h('span', { className: '__wg_err' }, error) : null,
        ),

        file ? h('span', { className: '__wg_note', style: { wordBreak: 'break-all' } }, '配置文件：' + file) : null,
        h('span', { className: '__wg_note' }, '改的是运行时覆盖，叠加在 profile 配置之上；不会修改 cordis.patch.yml。'),
      )
    }

    /* ── 插件 ────────────────────────────────────────────────────────────── */

    var inject = ['slots']

    function apply(ctx) {
      ensureCss()
      ctx.slots.inject('settings.section', function () {
        return ctx.slots.register(
          { name: 'settings.section', id: 'write-guard', order: 27, label: '写入防护' },
          function () {
            return h(Panel, {})
          },
        )
      })
    }

    exports.apply = apply
    exports.inject = inject
    return module.exports
  },
})
}
