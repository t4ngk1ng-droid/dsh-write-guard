import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../index.js'

/** Mount with a fake webServer so the settings route can be exercised. */
function mount() {
  const home = mkdtempSync(join(tmpdir(), 'wg-route-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const routes = new Map()
  const webServer = {
    register(route) {
      routes.set(`${route.path}`, route)
      return () => routes.delete(route.path)
    },
  }
  apply(
    {
      on() {},
      logger: { warn() {}, info() {} },
      tools: { register() {} },
      get: (name) => (name === 'webServer' ? webServer : undefined),
    },
    { audit: false, integrity: false, quarantine: false, notify: false },
  )
  return {
    home,
    routes,
    restore() {
      if (previous === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previous
      rmSync(home, { recursive: true, force: true })
    },
  }
}

/** Minimal req/res doubles that collect whatever the handler writes. */
function call(route, method, body) {
  return new Promise((resolve) => {
    const listeners = {}
    const req = {
      method,
      on(event, fn) {
        listeners[event] = fn
      },
    }
    const res = {
      statusCode: 0,
      headers: {},
      setHeader(k, v) {
        this.headers[k] = v
      },
      end(payload) {
        resolve({ code: this.statusCode, body: payload ? JSON.parse(payload) : null })
      },
    }
    const pending = route.handler(req, res)
    if (method === 'POST') {
      if (listeners.data && body !== undefined) listeners.data(Buffer.from(JSON.stringify(body)))
      if (listeners.end) listeners.end()
    }
    Promise.resolve(pending).catch((e) => resolve({ code: 0, body: { error: String(e) } }))
  })
}

test('the settings route is registered', () => {
  const m = mount()
  assert.ok(m.routes.has('/dsh-write-guard/config'))
  m.restore()
})

test('GET returns the live switches', async (t) => {
  const m = mount()
  t.after(m.restore)
  const { code, body } = await call(m.routes.get('/dsh-write-guard/config'), 'GET')
  assert.equal(code, 200)
  assert.equal(body.ok, true)
  assert.equal(body.config.mode, 'enforce')
  assert.ok(body.config.shellChecks.download)
  assert.deepEqual(body.restartOnly.includes('audit'), true)
})

test('POST applies a nested patch', async (t) => {
  const m = mount()
  t.after(m.restore)
  const route = m.routes.get('/dsh-write-guard/config')
  const { code, body } = await call(route, 'POST', { set: { shellChecks: { extract: false } } })
  assert.equal(code, 200)
  assert.equal(body.config.shellChecks.extract, false)
  assert.equal(body.config.shellChecks.download, true)
})

test('POST clear restores defaults', async (t) => {
  const m = mount()
  t.after(m.restore)
  const route = m.routes.get('/dsh-write-guard/config')
  await call(route, 'POST', { set: { shellChecks: { extract: false } } })
  const { body } = await call(route, 'POST', { clear: ['shellChecks'] })
  assert.equal(body.config.shellChecks.extract, true)
})

test('a non-GET/POST method is rejected', async (t) => {
  const m = mount()
  t.after(m.restore)
  const { code } = await call(m.routes.get('/dsh-write-guard/config'), 'DELETE')
  assert.equal(code, 405)
})
