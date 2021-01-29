const puppeteer = require('puppeteer')
const { expect } = require('chai')
const _ = require('lodash')
const server = require('./server').server
const globalVariables = _.pick(global, ['browser', 'expect', 'page'])

// puppeteer options
const opts = {
  headless: true
  // slowMo: 100,
  // timeout: 10000
}

// expose variables
before(async function () {
  await server.listen(38000)
  global.expect = expect
  global.browser = await puppeteer.launch(opts)
  global.page = await browser.newPage()
  await page.goto('http://localhost:38000/')
  page.on('console', message => console.log(`${message.text()}`))
})

// close page, browser, server and reset global variables
after(async function () {
  await page.close()
  await browser.close()
  global.browser = globalVariables.browser
  global.expect = globalVariables.expect
  await server.close()
})
