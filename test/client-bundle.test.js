import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'

const source = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8')

function sandbox() {
  const loads = []
  const window = { __ModuleLoader__: { load: (registration) => loads.push(registration.id) } }
  return { window, loads, context: { window, console } }
}

test('the bundle does not touch window when imported without one', () => {
  assert.doesNotThrow(() => runInNewContext(source, { console }))
})

test('the bundle registers under the package name', () => {
  const box = sandbox()
  runInNewContext(source, box.context)
  // client-modules matches the registration against the loader entry's name,
  // which is the package name — not the shorter entry id.
  assert.deepEqual(box.loads, ['dsh-write-guard'])
})

test('the panel lists every shell category the config defines', async () => {
  const { normalizeConfig } = await import('../lib/config.js')
  const config = normalizeConfig({})
  const block = source.slice(source.indexOf('var SHELL_CHECKS = ['), source.indexOf('var CONTENT_CHECKS'))
  const shown = [...block.matchAll(/\['([a-z-]+)'/g)].map((m) => m[1])
  assert.deepEqual(shown.sort(), Object.keys(config.shellChecks).sort())
})

test('the panel lists every content category the config defines', async () => {
  const { normalizeConfig } = await import('../lib/config.js')
  const config = normalizeConfig({})
  const block = source.slice(source.indexOf('var CONTENT_CHECKS = ['), source.indexOf('var SWITCHES'))
  const shown = [...block.matchAll(/\['([a-z-]+)'/g)].map((m) => m[1])
  assert.deepEqual(shown.sort(), Object.keys(config.contentChecks).sort())
})

test('every panel-editable key is in the host whitelist', async () => {
  const host = (await import('node:fs')).readFileSync(new URL('../index.js', import.meta.url), 'utf8')
  const block = host.slice(host.indexOf('const RUNTIME_KEYS = new Set(['), host.indexOf('])', host.indexOf('const RUNTIME_KEYS')))
  const hostKeys = new Set([...block.matchAll(/'([a-zA-Z]+)'/g)].map((m) => m[1]))
  const edit = source.slice(source.indexOf('var EDITABLE_KEYS = ['), source.indexOf(']', source.indexOf('var EDITABLE_KEYS')))
  const clientKeys = [...edit.matchAll(/'([a-zA-Z]+)'/g)].map((m) => m[1])
  const missing = clientKeys.filter((k) => !hostKeys.has(k))
  assert.deepEqual(missing, [], `panel writes keys the host rejects: ${missing.join(', ')}`)
})
