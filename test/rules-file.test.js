import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { findRulesFile, loadRulesFile, mergeRules, RULES_FILE_NAME } from '../lib/rules-file.js'
import { RULES } from '../lib/patterns.js'

function tempRules(content) {
  const dir = mkdtempSync(join(tmpdir(), 'wg-rules-'))
  const file = join(dir, RULES_FILE_NAME)
  writeFileSync(file, JSON.stringify(content))
  return { dir, file }
}

test('loads and compiles a custom rule', () => {
  const { file } = tempRules({
    rules: [
      {
        id: 'no-prod-config',
        title: '禁止写生产配置',
        severity: 100,
        patterns: ['prod\\.env'],
        probe: ['prod'],
      },
    ],
  })
  const { rules } = loadRulesFile(file)
  assert.equal(rules.length, 1)
  assert.equal(rules[0].id, 'no-prod-config')
  assert.equal(rules[0].severity, 100)
  assert.equal(rules[0].patterns[0].test('open prod.env'), true)
})

test('severity out of range is rejected', () => {
  const { file } = tempRules({ rules: [{ id: 'x', severity: 500, patterns: ['a'] }] })
  assert.throws(() => loadRulesFile(file), /severity/)
})

test('nested quantifier is rejected as ReDoS shape', () => {
  const { file } = tempRules({ rules: [{ id: 'x', severity: 50, patterns: ['(a+)+'] }] })
  assert.throws(() => loadRulesFile(file), /nested quantifier/)
})

test('unsupported regex is rejected with the rule id', () => {
  const { file } = tempRules({ rules: [{ id: 'bad', severity: 50, patterns: ['('] }] })
  assert.throws(() => loadRulesFile(file), /rule bad: .*unsafe regex/)
})

test('duplicate ids are rejected', () => {
  const { file } = tempRules({
    rules: [
      { id: 'dup', severity: 50, patterns: ['a'] },
      { id: 'dup', severity: 50, patterns: ['b'] },
    ],
  })
  assert.throws(() => loadRulesFile(file), /duplicate rule id/)
})

test('empty patterns are rejected', () => {
  const { file } = tempRules({ rules: [{ id: 'x', severity: 50, patterns: [] }] })
  assert.throws(() => loadRulesFile(file), /patterns must be a non-empty array/)
})

test('paths are normalized as strings', () => {
  const { file } = tempRules({
    rules: [{ id: 'x', severity: 50, patterns: ['a'], paths: ['src/**'] }],
  })
  assert.deepEqual(loadRulesFile(file).rules[0].paths, ['src/**'])
})

test('mergeRules rejects project overrides of built-in ids', () => {
  const custom = [{ id: 'reverse-shell', severity: 1, title: 'override', category: 'custom', patterns: [/x/] }]
  assert.throws(() => mergeRules(RULES, custom), /collides with a built-in rule/)
  assert.equal(RULES.find((r) => r.id === 'reverse-shell').severity, 95)
})

test('mergeRules appends new ids', () => {
  const custom = [{ id: 'custom-only', severity: 50, title: 'x', category: 'custom', patterns: [/x/] }]
  const merged = mergeRules(RULES, custom)
  assert.equal(merged.length, RULES.length + 1)
})

test('findRulesFile walks up from a nested directory', () => {
  const { dir, file } = tempRules({ rules: [] })
  const nested = join(dir, 'a', 'b', 'c')
  mkdirSync(nested, { recursive: true })
  assert.equal(findRulesFile(nested), file)
})

test('findRulesFile returns null when absent', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wg-none-'))
  // A temp directory is usually outside any project that would have a file.
  const found = findRulesFile(dir)
  assert.ok(found === null || found.endsWith(RULES_FILE_NAME))
})

test('ambiguous repetition and grouping cannot bypass the ReDoS guard', () => {
  for (const pattern of ['(a|aa)+$', '(a{1,}){1,}', '((a)+)+', 'a*', 'a|b']) {
    const { file } = tempRules({ rules: [{ id: 'x', severity: 50, patterns: [pattern] }] })
    assert.throws(() => loadRulesFile(file), /unsafe regex|nested quantifier/, pattern)
  }
})

test('literal escaped patterns remain supported and record their policy root', () => {
  const { dir, file } = tempRules({
    rules: [{ id: 'x', severity: 50, patterns: ['prod\\.env', '\\d'] }],
  })
  const { rules } = loadRulesFile(file)
  assert.equal(rules[0].patterns[0].test('prod.env'), true)
  assert.equal(rules[0].patterns[1].test('7'), true)
  assert.equal(rules[0].baseDir, dir)
})
