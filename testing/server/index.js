'use strict'

const fs = require('fs')
const http = require('http')
const pkgJson = require('../../package.json')

const indexHtml = `<!DOCTYPE html>
  <html>
  <head>
    <meta http-equiv="content-type" content="text/html; charset=utf-8" />
    <title>${pkgJson.name}</title>
  </head>

  <body>

  </body>
  <script type="module">
      import * as _pkg from '/index.browser.bundle.mod.js'
      window._pkg = _pkg
    </script>
  </html>`

class TestServer {
  constructor () {
    this.server = http.createServer(function (req, res) {
      if (req.url === '/index.browser.bundle.mod.js') {
        fs.readFile(pkgJson.browser, function (err, data) {
          if (err) {
            res.writeHead(404)
            res.end(JSON.stringify(err))
            return
          }
          res.writeHead(200, { 'Content-Type': 'text/javascript' })
          res.end(data)
        })
      } else if (req.url === '/index.html' || req.url === '/') {
        res.writeHead(200)
        res.end(indexHtml)
      } else {
        res.writeHead(404)
        res.end()
      }
    })
  }

  listen (port = 38080) {
    return new Promise((resolve, reject) => {
      this.server.listen(port, error => (error) ? reject(error) : resolve())
    })
  }

  close () {
    return new Promise((resolve, reject) => {
      this.server.close(error => (error) ? reject(error) : resolve())
    })
  }
}

exports.server = new TestServer()
