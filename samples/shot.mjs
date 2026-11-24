import { chromium } from 'file:///C:/Users/Lenovo/AppData/Roaming/CherryStudio/Data/Agents/b3c24e6d-0261-42ba-ada2-9b7d3a135cd1/freelancer-monitor/node_modules/playwright-core/index.mjs'
import { pathToFileURL } from 'node:url'

const src = pathToFileURL('C:/Users/Lenovo/.dsh/plugins/dsh-write-guard/samples/dryrun-shot.html').href
let browser
for (const channel of ['msedge', 'chrome', undefined]) {
  try { browser = await chromium.launch(channel ? { channel } : {}); break } catch {}
}
const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 })
await page.goto(src, { waitUntil: 'load' })
await page.waitForTimeout(300)
const h = await page.evaluate(() => Math.ceil(document.body.scrollHeight))
await page.setViewportSize({ width: 1280, height: h })
await page.waitForTimeout(150)
await page.screenshot({ path: 'C:/Users/Lenovo/Desktop/dsh-write-guard-dryrun.png', clip: { x: 0, y: 0, width: 1280, height: h } })
await browser.close()
console.log('saved, height =', h)
