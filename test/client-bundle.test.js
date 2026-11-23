import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'

const source = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8')

/** Run the bundle in a browser-ish sandbox and count registrations. */
function sandbox() {
  const loads = []
  const window = {
    __ModuleLoader__: {
      load: (registration) => loads.push(registration.id),
    },
  }
  return { window, loads, context: { window, console } }
}

test('the bundle does not touch window when imported without one', () => {
  assert.doesNotThrow(() => runInNewContext(source, { console }))
})

test('the bundle registers exactly once per page', () => {
  const box = sandbox()
  runInNewContext(source, box.context)
  runInNewContext(source, box.context)
  assert.deepEqual(box.loads, ['write-guard'])
})

test('the registered id matches the loader entry name', () => {
  const box = sandbox()
  runInNewContext(source, box.context)
  assert.equal(box.loads[0], 'write-guard')
})
