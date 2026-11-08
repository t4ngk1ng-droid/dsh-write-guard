import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createAudit, verifyChain } from '../lib/audit.js'

function auditFile(prefix) {
  return join(mkdtempSync(join(tmpdir(), prefix)), 'audit.jsonl')
}

test('rotation starts a new independently valid segment', async () => {
  const file = auditFile('wg-a-rotate-')
  const audit = createAudit({ file, maxBytes: 256, hashChain: true })
  audit.append({ event: 'a', text: 'x'.repeat(200) })
  audit.append({ event: 'b', text: 'y'.repeat(200) })
  audit.append({ event: 'c', text: 'z'.repeat(200) })
  await audit.close()

  assert.equal(verifyChain(file).ok, true)
  const segments = readdirSync(join(file, '..')).filter((name) => name.startsWith('audit.jsonl.'))
  assert.ok(segments.length >= 2)
  for (const segment of segments) assert.equal(verifyChain(join(file, '..', segment)).ok, true, segment)
})

test('closing and reopening resumes the previous head', async () => {
  const file = auditFile('wg-a-reopen-')
  const first = createAudit({ file, hashChain: true })
  first.append({ event: 'first' })
  await first.close()
  const second = createAudit({ file, hashChain: true })
  second.append({ event: 'second' })
  await second.close()
  const result = verifyChain(file)
  assert.equal(result.ok, true)
  assert.equal(result.records, 2)
})

test('independent instances sharing a file preserve one chain', async () => {
  const file = auditFile('wg-a-shared-')
  const first = createAudit({ file, hashChain: true })
  const second = createAudit({ file, hashChain: true })
  for (let i = 0; i < 20; i++) {
    first.append({ event: 'first', i })
    second.append({ event: 'second', i })
  }
  await Promise.all([first.close(), second.close()])
  const result = verifyChain(file)
  assert.equal(result.ok, true)
  assert.equal(result.records, 40)
})

test('a missing audit file is not reported as a verified empty chain', () => {
  const file = join(mkdtempSync(join(tmpdir(), 'wg-a-missing-')), 'none.jsonl')
  const result = verifyChain(file)
  assert.equal(result.ok, false)
  assert.match(result.reason, /does not exist/)
})

test('concurrent close calls share the same flush point', async () => {
  const file = auditFile('wg-a-close-')
  const audit = createAudit({ file, hashChain: true })
  audit.append({ event: 'one' })
  const first = audit.close()
  const second = audit.close()
  assert.equal(first, second)
  await Promise.all([first, second])
  assert.equal(readFileSync(file, 'utf8').trim().split('\n').length, 1)
  assert.equal(verifyChain(file).ok, true)
})
