
import http from 'http'

const { WalletProtocol, HttpInitiatorTransport, HttpResponderTransport } = _pkg

type HttpType = typeof http

describe('Protocol execution using HTTP', function () {
  if (IS_BROWSER) {
    console.warn('The protocol can only be fully tested on node since browsers cannot start services')
    return
  }

  const http: HttpType = require('http') // eslint-disable-line

  const responderTransport = new HttpResponderTransport()
  responderTransport.use((req: any, res: any) => {
    chai.expect(req.walletProtocol).to.be.equal(true)
    res.end(Buffer.from(JSON.stringify({
      url: req.url,
      method: req.method,
      body: req.body
    })))
  })
  const responder = new WalletProtocol(responderTransport)
  const server = http.createServer((req, res) => {
    responderTransport.dispatchRequest(req, res).catch((ex: any) => {
      console.log('some error here', ex)
      server.close()
    })
  })

  const initiatorTransport = new HttpInitiatorTransport({
    async getConnectionString () {
      const connStringPromise = new Promise<string>(resolve => {
        const interval = setInterval(() => {
          const connString = responderTransport.connString
          if (connString !== undefined) {
            clearInterval(interval)
            resolve(connString.toString())
          }
        }, 500)
      })
      return await connStringPromise
    }
  })
  const initiator = new WalletProtocol(initiatorTransport)
  let session: _pkgTypes.Session<_pkgTypes.HttpInitiatorTransport> | undefined
  initiator.on('masterKey', (mkey: any) => {
    console.log('master key', mkey.toJSON())
  })

  // Setup the timeout
  this.timeout(responderTransport.timeout + 1000)

  this.beforeAll(async () => {
    await new Promise<void>(resolve => {
      server.listen(responderTransport.port, resolve)
    })
  })

  it('Should run properly', async () => {
    await Promise.all([
      responder.run(),
      initiator.run().then((s: _pkgTypes.Session<any>) => {
        session = s
      })
    ])
  })

  it('Should exchange authenticated and encrypted messages', async () => {
    if (session === undefined) {
      throw new Error('This test can only be executed if protocol runs properly')
    }
    const res = await session.send({
      url: '/identities',
      init: {
        method: 'GET'
      }
    })
    console.log(res.body)
  })

  this.afterAll(async () => {
    server.close()
  })
})
