const puppeteer = require('puppeteer')

const browserTests = async ({ doNotLogWarnings = true, serverPort = 38000, keepServerRunning = false, puppeteerOptions = {} }) => {
  const server = require('./server').server
  await server.init()
  await server.listen(serverPort)
  const browser = await puppeteer.launch(puppeteerOptions)
  const page = await browser.newPage()
  page.on('console', function (message) {
    let ignore = message.type() === 'warning' && doNotLogWarnings
    if (message.type() === 'error' && message.location()) {
      if (message.location().url.includes('favicon.ico')) {
        ignore = true
      }
    }
    if (ignore) return

    let text = (message.args().length > 0) ? message.args()[0]._remoteObject.value : message.text()
    const args = []
    if (message.args() !== undefined && message.args().length > 1) {
      for (let i = 1; i < message.args().length; i++) {
        args.push(message.args()[i]._remoteObject.value)
      }
    }

    if (message.type() === 'error' && message.location()) {
      text = `${message.location().url} : ${text}`
    }
    console[message.type()](`${text}`, ...args)
  })
  page.on('error', function (err) { page.emit(new Error(err)) })

  await page.goto('http://localhost:38000/')
  const watchDog = page.waitForFunction('_mocha.state === \'stopped\'')
  await watchDog

  if (keepServerRunning === false) {
    await page.close()
    await browser.close()
    await server.close()
  }
}

const opts = {
  // puppeteer options
  puppeteerOptions: {
    headless: true
    // slowMo: 100,
    // timeout: 10000
  },
  doNotLogWarnings: true,
  keepServerRunning: false, // keep server running until manually closed with ctrl-c. In combination with puppeteerOptions.headless (or just connecting any browser to the test page) allows debugging in browser
  serverPort: 38000
}
browserTests(opts)
