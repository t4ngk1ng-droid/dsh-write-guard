import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../index.js'

function mount(extra = {}) {
  const home = mkdtempSync(join(tmpdir(), 'wg-cfg-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const tools = new Map()
  const hooks = new Map()
  apply(
    {
      on: (e, h) => hooks.set(e, h),
      logger: { warn() {}, info() {} },
      tools: { register: (tool) => tools.set(tool.name, tool) },
    },
    { audit: false, integrity: false, quarantine: false, notify: false, ...extra },
  )
  return {
    home,
    tools,
    hooks,
    restore() {
      if (previous === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previous
      rmSync(home, { recursive: true, force: true })
    },
  }
}

const decide = async (hook, command, name = 'pwsh') => {
  let allowed = false
  const result = await hook(
    { name, callId: 'c1', agent: { session: { header: { cwd: 'C:\w' } } }, arguments: { command } },
    () => {
      allowed = true
      return { kind: 'allow' }
    },
  )
  return allowed ? 'allow' : result.kind
}

test('write_guard_config lists switches when called with no arguments', async (t) => {
  const m = mount()
  t.after(m.restore)
  const tool = m.tools.get('write_guard_config')
  assert.ok(tool, 'tool registered')
  const result = await tool.execute({}, {})
  assert.equal(result.config.mode, 'enforce')
  assert.ok(result.available['Shell 写入'].includes('shellChecks'))
})

test('a runtime switch takes effect immediately and persists', async (t) => {
  const m = mount()
  t.after(m.restore)
  const tool = m.tools.get('write_guard_config')
  const hook = m.hooks.get('tools/pre-execute')
  assert.equal(await decide(hook, 'tar -xzf a.tgz'), 'ask')

  const changed = await tool.execute({ set: { shellChecks: { extract: false } } }, {})
  assert.equal(changed.ok, true)
  assert.equal(await decide(hook, 'tar -xzf a.tgz'), 'allow')

  const saved = JSON.parse(readFileSync(join(m.home, 'write-guard', 'config.json'), 'utf8'))
  assert.deepEqual(saved.shellChecks, { extract: false })
})

test('setting one category leaves the others alone', async (t) => {
  const m = mount()
  t.after(m.restore)
  const tool = m.tools.get('write_guard_config')
  await tool.execute({ set: { shellChecks: { extract: false } } }, {})
  const after = await tool.execute({ set: { shellChecks: { download: false } } }, {})
  assert.equal(after.config.shellChecks.extract, false)
  assert.equal(after.config.shellChecks.download, false)
  assert.equal(after.config.shellChecks.tee, true)
})

test('clear reverts an override to the shipped default', async (t) => {
  const m = mount()
  t.after(m.restore)
  const tool = m.tools.get('write_guard_config')
  await tool.execute({ set: { shellChecks: { extract: false } } }, {})
  const cleared = await tool.execute({ clear: ['shellChecks'] }, {})
  assert.equal(cleared.config.shellChecks.extract, true)
})

test('mode can be flipped at runtime', async (t) => {
  const m = mount()
  t.after(m.restore)
  const tool = m.tools.get('write_guard_config')
  const changed = await tool.execute({ set: { mode: 'dry-run' } }, {})
  assert.equal(changed.config.mode, 'dry-run')
})

test('an invalid override file does not break mounting', async (t) => {
  const m = mount()
  t.after(m.restore)
  const fs = await import('node:fs')
  fs.mkdirSync(join(m.home, 'write-guard'), { recursive: true })
  fs.writeFileSync(join(m.home, 'write-guard', 'config.json'), '{not json', { encoding: 'utf8' })
  assert.ok(existsSync(join(m.home, 'write-guard', 'config.json')))
  const tool = m.tools.get('write_guard_config')
  const result = await tool.execute({}, {})
  assert.equal(result.config.mode, 'enforce')
})
