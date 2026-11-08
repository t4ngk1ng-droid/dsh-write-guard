import { test } from 'node:test'
import assert from 'node:assert/strict'

import { scanEntropy, shannonEntropy } from '../lib/entropy.js'

const config = { threshold: 4.5, minLength: 200 }

test('random base64-like payload is flagged', () => {
  // A uniform sweep of the 64-symbol base64 alphabet: deterministic, and its
  // entropy is exactly log2(64) = 6 bits per symbol.
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const s = (chars.repeat(7) + chars.slice(0, 16)).slice(0, 400)
  const runs = scanEntropy(s, config)
  assert.equal(runs.length, 1)
  assert.ok(runs[0].entropy >= 4.5)
})

test('ordinary English prose is not flagged', () => {
  const text = 'The quick brown fox jumps over the lazy dog. '.repeat(20)
  assert.equal(scanEntropy(text, config).length, 0)
})

test('CJK prose is not flagged', () => {
  const text = '这是一个普通的中文句子，用来测试熵检测不会误报。'.repeat(20)
  assert.equal(scanEntropy(text, config).length, 0)
})

test('short tokens are not flagged', () => {
  const text = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo'
  assert.equal(scanEntropy(text, config).length, 0)
})

test('repeated characters have zero entropy', () => {
  assert.equal(shannonEntropy('aaaaaaaa'), 0)
})

test('uniform distribution approaches log2(alphabet)', () => {
  const entropy = shannonEntropy('abcd'.repeat(100))
  assert.ok(Math.abs(entropy - 2) < 0.001)
})

test('runs are capped', () => {
  const blob = 'A'.repeat(0) + 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldY'.repeat(60)
  const runs = scanEntropy(blob, { ...config, maxRuns: 2 })
  assert.ok(runs.length <= 2)
})

test('high-entropy hex can be detected below the base64 cutoff', () => {
  const blob = '0123456789abcdef'.repeat(20)
  const runs = scanEntropy(blob, config)
  assert.equal(runs.length, 1)
  assert.ok(runs[0].entropy >= 3.5 && runs[0].entropy <= 4)
})
