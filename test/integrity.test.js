import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { fingerprint, verifyIntegrity } from '../lib/integrity.js'

function tempRoot(files) {
  const dir = mkdtempSync(join(tmpdir(), 'wg-int-'))
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

test('first run writes a baseline', () => {
  const root = tempRoot({ 'index.js': 'export const a = 1', 'lib/x.js': 'export const b = 2' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  const result = verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  assert.equal(result.status, 'baseline')
})

test('unchanged files verify ok', () => {
  const root = tempRoot({ 'index.js': 'x' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  assert.equal(verifyIntegrity({ root, baselineFile, version: '0.1.0' }).status, 'ok')
})

test('a modified file is reported as tampered', () => {
  const root = tempRoot({ 'index.js': 'x', 'lib/a.js': 'a' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  writeFileSync(join(root, 'lib/a.js'), 'evil')
  const result = verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  assert.equal(result.status, 'tampered')
  assert.ok(result.changed.includes('lib/a.js'))
})

test('a deleted file is reported as missing', () => {
  const root = tempRoot({ 'index.js': 'x', 'lib/gone.js': 'a' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  unlinkSync(join(root, 'lib/gone.js'))
  const result = verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  assert.equal(result.status, 'tampered')
  assert.ok(result.missing.includes('lib/gone.js'))
})

test('version changes do not authorize a changed tree or rewrite the baseline', () => {
  const root = tempRoot({ 'index.js': 'x', 'package.json': '{"version":"0.1.0"}' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  writeFileSync(join(root, 'index.js'), 'changed by an alleged upgrade')
  writeFileSync(join(root, 'package.json'), '{"version":"0.2.0"}')
  const before = readFileSync(baselineFile, 'utf8')
  const result = verifyIntegrity({ root, baselineFile, version: '0.2.0' })
  assert.equal(result.status, 'tampered')
  assert.equal(result.versionChanged, true)
  assert.equal(readFileSync(baselineFile, 'utf8'), before)
})

test('entry configuration, tests and scripts are fingerprinted', () => {
  const root = tempRoot({
    'index.js': 'x',
    'package.json': '{"main":"index.js"}',
    'cordis.patch.yml': 'mode: enforce',
    'test/a.test.js': 'test',
    'scripts/smoke.mjs': 'smoke',
  })
  const files = Object.keys(fingerprint(root))
  assert.deepEqual(files, ['cordis.patch.yml', 'index.js', 'package.json', 'scripts/smoke.mjs', 'test/a.test.js'])
})

test('a corrupt baseline is tampered and is never replaced automatically', () => {
  const root = tempRoot({ 'index.js': 'x' })
  const baselineFile = join(mkdtempSync(join(tmpdir(), 'wg-base-')), 'integrity.json')
  writeFileSync(baselineFile, '{not json')
  const result = verifyIntegrity({ root, baselineFile, version: '0.1.0' })
  assert.equal(result.status, 'tampered')
  assert.equal(readFileSync(baselineFile, 'utf8'), '{not json')
})
