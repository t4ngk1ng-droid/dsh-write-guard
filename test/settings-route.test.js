import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { apply } from '../index.js'

/** Mount with a fake webServer; `conn` controls the trust fence. */
function mount(options = {}) {
  const home = mkdtempSync(join(tmpdir(), 'wg-route-'))
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const routes = new Map()
  const webServer = {
    register(route) {
      routes.set(route.path, route)
      return () => routes.delete(route.path)
    },
  }
  const services = {
    webServer,
    ...(options.conn === undefined ? {} : { connection: options.conn }),
  }
  apply(
    {
      on() {},
      logger: { warn() {}, info() {} },
      tools: { register() {} },
      get: (name) => services[name],
    },
    { audit: false, integrity: false, quarantine: false, notify: false },
  )
  return {
    home,
    routes,
    configFile: join(home, 'write-guard', 'config.json'),
    restore() {
      if (previous === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = previous
      rmSync(home, { recursive: true, force: true })
    },
  }
}

/** Minimal req/res doubles. `body` is a string so size limits can be tested. */
function call(route, method, body) {
  return new Promise((resolve) => {
    const listeners = {}
    const req = {
      method,
      readableEnded: false,
      on(event, fn) {
        listeners[event] = fn
      },
    }
    const res = {
      statusCode: 0,
      setHeader() {},
      end(payload) {
        resolve({ code: this.statusCode, body: payload ? JSON.parse(payload) : null })
      },
    }
    route.handler(req, res)
    if (method === 'POST' || body !== undefined) {
      if (body !== undefined && listeners.data) listeners.data(Buffer.from(body, 'utf8'))
      req.readableEnded = true
      if (listeners.end) listeners.end()
    }
  })
}

const allowAll = { requestRejection: () => undefined }

test('the settings route is registered', () => {
  const m = mount({ conn: allowAll })
  assert.ok(m.routes.has('/dsh-write-guard/config'))
  m.restore()
})

test('GET returns the live switches and no absolute path', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const { code, body } = await call(m.routes.get('/dsh-write-guard/config'), 'GET')
  assert.equal(code, 200)
  assert.equal(body.config.mode, 'enforce')
  assert.ok(!body.file.includes(':'), `file should be logical, got ${body.file}`)
  assert.ok(body.restartOnly.includes('audit'))
  assert.ok(!body.restartOnly.includes('quarantine'), 'quarantine applies immediately')
})

test('a missing trust fence is a rejection, not a pass', async (t) => {
  const m = mount({}) // no connection service
  t.after(m.restore)
  const { code, body } = await call(m.routes.get('/dsh-write-guard/config'), 'GET')
  assert.equal(code, 503)
  assert.equal(body.ok, false)
  assert.equal(existsSync(m.configFile), false)
})

test('a throwing trust fence is a rejection', async (t) => {
  const m = mount({
    conn: {
      requestRejection() {
        throw new Error('boom')
      },
    },
  })
  t.after(m.restore)
  const { code } = await call(m.routes.get('/dsh-write-guard/config'), 'GET')
  assert.equal(code, 503)
})

test('POST applies a nested patch', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const { code, body } = await call(
    m.routes.get('/dsh-write-guard/config'),
    'POST',
    JSON.stringify({ set: { shellChecks: { extract: false } } }),
  )
  assert.equal(code, 200)
  assert.equal(body.config.shellChecks.extract, false)
  assert.equal(body.config.shellChecks.download, true)
})

test('POST clear restores defaults', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const route = m.routes.get('/dsh-write-guard/config')
  await call(route, 'POST', JSON.stringify({ set: { shellChecks: { extract: false } } }))
  const { body } = await call(route, 'POST', JSON.stringify({ clear: ['shellChecks'] }))
  assert.equal(body.config.shellChecks.extract, true)
})

test('a non-GET/POST method is rejected', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const { code } = await call(m.routes.get('/dsh-write-guard/config'), 'DELETE')
  assert.equal(code, 405)
})

test('an oversized body is rejected with 413 and writes nothing', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const big = JSON.stringify({ set: { mode: 'dry-run' }, pad: 'x'.repeat(80 * 1024) })
  const { code } = await call(m.routes.get('/dsh-write-guard/config'), 'POST', big)
  assert.equal(code, 413)
  assert.equal(existsSync(m.configFile), false)
})

test('invalid json is rejected with 400 and writes nothing', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const { code } = await call(m.routes.get('/dsh-write-guard/config'), 'POST', '{not json')
  assert.equal(code, 400)
  assert.equal(existsSync(m.configFile), false)
})

test('unknown and prototype keys are rejected', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const route = m.routes.get('/dsh-write-guard/config')
  // `__proto__` must come from raw JSON: as an object literal it would set the
  // prototype of the literal itself and never reach the server.
  const protoAttack = JSON.parse('{"set":{"__proto__":{"polluted":true}}}')
  for (const payload of [
    { set: { nope: true } },
    protoAttack,
    { set: { shellChecks: { nope: true } } },
    { set: { shellChecks: { extract: 'yes' } } },
    { clear: ['nope'] },
    JSON.parse('{"clear":["__proto__"]}'),
  ]) {
    const { code } = await call(route, 'POST', JSON.stringify(payload))
    assert.equal(code, 400, JSON.stringify(payload))
  }
  assert.equal(existsSync(m.configFile), false)
  assert.equal({}.polluted, undefined)
})

test('only the changed key reaches the override file', async (t) => {
  const m = mount({ conn: allowAll })
  t.after(m.restore)
  const route = m.routes.get('/dsh-write-guard/config')
  await call(route, 'POST', JSON.stringify({ set: { mode: 'dry-run' } }))
  const saved = JSON.parse(readFileSync(m.configFile, 'utf8'))
  assert.deepEqual(saved, { mode: 'dry-run' })
})
