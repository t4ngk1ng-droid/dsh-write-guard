import { test } from 'node:test'
import assert from 'node:assert/strict'

import { DEFAULT_CONFIG, normalizeConfig } from '../lib/config.js'

test('secure defaults stay secure', () => {
  const c = normalizeConfig({})
  assert.equal(c.mode, 'enforce')
  assert.deepEqual(c.ignorePaths, [])
  assert.equal(c.verifyWrites, true)
  assert.equal(c.verifyPolicy, 'block')
  assert.equal(c.shellGuard, true)
  assert.equal(c.shellUnknownPolicy, 'ask')
  assert.equal(c.truncatePolicy, 'ask')
  assert.equal(c.onScannerError, 'ask')
  assert.equal(c.blockBinaries, true)
  assert.equal(c.entropy, true)
  assert.equal(c.homoglyph, true)
  assert.equal(c.integrity, true)
  assert.equal(c.audit, true)
  assert.equal(c.quarantine, true)
  assert.equal(c.notify, false)
})

test('invalid mode falls back to enforce', () => {
  assert.equal(normalizeConfig({ mode: 'offf' }).mode, 'enforce')
})

test('ask threshold is clamped to the block threshold', () => {
  const c = normalizeConfig({ blockThreshold: 50, askThreshold: 90 })
  assert.equal(c.askThreshold, 50)
})

test('ignorePaths must be an array', () => {
  assert.deepEqual(normalizeConfig({ ignorePaths: '**/x' }).ignorePaths, [])
  assert.deepEqual(normalizeConfig({ ignorePaths: ['**/x'] }).ignorePaths, ['**/x'])
})

test('removed customRules config is not advertised', () => {
  assert.equal(Object.hasOwn(DEFAULT_CONFIG, 'customRules'), false)
})
