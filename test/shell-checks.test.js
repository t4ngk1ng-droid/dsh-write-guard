import { test } from 'node:test'
import assert from 'node:assert/strict'

import { apply } from '../index.js'

/** Mount the plugin with the given config and return its pre-execute hook. */
function mount(config) {
  const hooks = new Map()
  apply(
    { on: (event, hook) => hooks.set(event, hook), logger: { warn() {}, info() {} }, tools: { register() {} } },
    { audit: false, integrity: false, quarantine: false, notify: false, ...config },
  )
  return hooks.get('tools/pre-execute')
}

/** `next()` is the allow path, so calling it means the write was not flagged. */
async function decide(hook, command, name = 'pwsh') {
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

test('a disabled download check lets a download through', async () => {
  assert.equal(await decide(mount({ shellChecks: { download: false } }), 'irm https://e.com/x -OutFile d.ps1'), 'allow')
})

test('a download check left on still asks', async () => {
  assert.equal(await decide(mount({}), 'irm https://e.com/x -OutFile d.ps1'), 'ask')
})

test('disabling one category does not disable another', async () => {
  assert.equal(await decide(mount({ shellChecks: { download: false } }), 'tar -xzf a.tgz'), 'ask')
})

test('a disabled extract check lets an extraction through', async () => {
  assert.equal(await decide(mount({ shellChecks: { extract: false } }), 'tar -xzf a.tgz'), 'allow')
})

test('a disabled redirect check lets a plain redirect through', async () => {
  assert.equal(await decide(mount({ shellChecks: { redirect: false } }), 'echo hi > a.txt', 'bash'), 'allow')
})

test('an unknown switch name is ignored rather than disabling anything', async () => {
  assert.equal(await decide(mount({ shellChecks: { nope: false } }), 'irm https://e.com/x -OutFile d.ps1'), 'ask')
})

test('switching every category off leaves ordinary commands alone', async () => {
  const hook = mount({
    shellChecks: { redirect: false, echo: false, heredoc: false, tee: false, download: false, extract: false, dotnet: false, cmdlets: false },
  })
  assert.equal(await decide(hook, 'irm https://e.com/x -OutFile d.ps1'), 'allow')
  assert.equal(await decide(hook, 'echo hi > a.txt', 'bash'), 'allow')
})
