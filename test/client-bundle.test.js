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
