import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../index.js'
import { RULES_FILE_NAME } from '../lib/rules-file.js'

test('enforce retains the last valid project rules across a malformed reload', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'wg-pre-cache-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  t.after(() => {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    rmSync(home, { recursive: true, force: true })
  })
  const file = join(home, RULES_FILE_NAME)
  writeFileSync(file, JSON.stringify({ rules: [{ id: 'policy-marker', patterns: ['project-marker'], severity: 90 }] }))
  const hooks = new Map(), warnings = []
  apply({ on: (event, hook) => hooks.set(event, hook), logger: { warn: m => warnings.push(m) }, tools: { register() {} } },
    { audit: false, integrity: false, quarantine: false })
  const exec = { name: 'write', callId: 'cached', agent: { session: { header: { cwd: home } } }, arguments: { file_path: 'a.txt', content: 'project-marker' } }
  const gate = () => hooks.get('tools/pre-execute')(exec, () => assert.fail('cached rule should deny'))
  assert.equal((await gate()).kind, 'deny')
  writeFileSync(file, '{')
  utimesSync(file, 1, 1) // distinct mtime even on a coarse-resolution filesystem
  assert.equal((await gate()).kind, 'deny')
  assert.ok(warnings.some(m => m.includes('keeping previous rules')))
})

for (const failure of ['project rules', 'scanner']) {
  for (const [mode, onScannerError, expectNext] of [
    ['dry-run', 'ask', true],
    ['enforce', 'ask', false],
    ['enforce', 'allow', true],
  ]) {
    test(`${mode}/${onScannerError} handles pre-execute ${failure} errors`, async (t) => {
      const home = mkdtempSync(join(tmpdir(), 'wg-pre-'))
      const previousHome = process.env.DSH_HOME
      process.env.DSH_HOME = home
      t.after(() => {
        if (previousHome === undefined) delete process.env.DSH_HOME
        else process.env.DSH_HOME = previousHome
        rmSync(home, { recursive: true, force: true })
      })

      const invalidRules = failure === 'project rules'
      writeFileSync(join(home, RULES_FILE_NAME), invalidRules ? '{' : '{"rules":[]}')
      const args = { file_path: 'notes.txt', content: 'hello' }
      if (!invalidRules) Object.defineProperty(args, 'content', { get() { throw new Error('test scan error') } })
      const warnings = []
      const hooks = new Map()
      apply({
        on: (event, hook) => hooks.set(event, hook),
        logger: { warn: (message) => warnings.push(message) },
        tools: { register() {} },
      }, { mode, onScannerError, integrity: false, audit: false, quarantine: false })

      const downstream = { kind: 'continue' }
      const next = t.mock.fn(() => downstream)
      const result = await hooks.get('tools/pre-execute')({
        name: 'write', arguments: args, agent: { session: { header: { cwd: home } } },
      }, next)
      const cause = invalidRules ? 'rules file rejected' : 'test scan error'
      assert.ok(warnings.some((message) => message.includes('scan failed') && message.includes(cause)))
      assert.equal(next.mock.callCount(), expectNext ? 1 : 0)
      if (expectNext) assert.equal(result, downstream)
      else assert.equal(result.kind, 'ask')
    })
  }
}
