import express, { Express } from 'express'
import http from 'http'

import { logger, Locals } from '@wallet/main/internal'
import { createServer, initServer } from './server'

export class ApiManager {
  protected server: http.Server
  protected app: Express
  protected locals: Locals
  protected port: number
  protected host: string

  constructor (locals: Locals) {
    this.app = express()
    locals.connectManager.walletProtocolTransport.use(this.app)
    this.server = createServer(locals.connectManager.handleRequest, {
      useHttps: false
    })
    this.locals = locals

    // Network settings
    this.port = locals.connectManager.walletProtocolTransport.port
    this.host = 'localhost'
  }

  async initialize (): Promise<void> {
    await initServer(this.app, this.locals)
  }

  async listen (): Promise<void> {
    const { host, port } = this
    await new Promise<void>((resolve) =>
      this.server.listen(port, host, () => {
        resolve()
      }))

    // Log connection information
    const publicUri = `http://localhost:${port}`
    logger.info(`Application is listening on port ${port}`)
    logger.info('Setup Developer Api to access to the following services:')
    logger.info(` - OpenAPI JSON spec at ${publicUri}/api-spec/openapi.json`)
    logger.info(` - OpenAPI browsable spec at ${publicUri}/api-spec/ui`)
    logger.info(` - Pairing form at ${publicUri}/pairing`)
  }

  async close (): Promise<void> {
    await new Promise<void>((resolve) => {
      this.server.close(() => {
        resolve()
      })
    })
  }
}
