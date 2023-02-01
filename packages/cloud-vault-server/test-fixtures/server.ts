import type { Server } from '../src'
before(async function () {
  try {
    const { default: serverPromise } = await import('../src')
    const server: Server | undefined = await serverPromise
    this.server = server
    await server.dbConnection.db.initialized
  } catch (error) {
    console.log('\x1b[91mALL TEST SKIPPED: A connection to a DB has not been setup\x1b[0m')
    this.skip()
  }
})

after(function (done) {
  const server: Server | undefined = this.server
  if (server !== undefined && server.server.listening) { // eslint-disable-line @typescript-eslint/prefer-optional-chain
    server.server.closeAllConnections()
    server.server.close((err) => {
      done(err)
    })
  } else {
    done()
  }
})
