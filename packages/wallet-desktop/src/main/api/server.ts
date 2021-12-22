import path from 'path'
import express, { Express, ErrorRequestHandler } from 'express'
// import cors from 'cors'
import https from 'https'
import http from 'http'
import { middleware as openapiValidator } from 'express-openapi-validator'
import swaggerUI from 'swagger-ui-express'
import { HttpError } from 'express-openapi-validator/dist/framework/types'
import openapiSpec from '@i3m/wallet-desktop-openapi'
import { WalletError } from '@i3m/base-wallet'

import {
  loggerMiddleware,
  setLocals,
  Locals,
  ActionError
} from '@wallet/main/internal'
import { developerApi } from './developer-api'

interface ServerConfig {
  useHttps: boolean
}

export function createServer (app: http.RequestListener, config: ServerConfig): http.Server {
  // Log cihpers
  // const ciphers = tls.getCiphers()
  // console.log(ciphers)

  let server: http.Server

  if (config.useHttps) {
    // Setup psk ssl
    const options: https.ServerOptions = {}

    const cipher = 'tls_aes_128_gcm_sha256'.toUpperCase()
    console.log(cipher)
    const key = Buffer.from('1b0d885fb69527dd11bea699be51af19', 'hex')
    console.log(key.toString('hex'))

    options.ciphers = cipher
    options.pskCallback = (socket, identity) => {
      (socket as any).identity = identity
      return key
    }

    server = https.createServer(options, app)

    // Setup events
    server.on('tlsClientError', (err) => {
      console.log(err)
    })
  } else {
    server = http.createServer(app)
  }

  return server
}

export async function initServer (app: Express, locals: Locals): Promise<void> {
  setLocals(app, locals)

  // Add middlewares
  app.use(express.json())
  app.use(loggerMiddleware)
  app.use(developerApi(locals))

  // Add default endpoint
  app.get('/', function (req, res) {
    res.redirect('/api-spec/ui')
  })

  // Add api-spec router
  const apiSpecRouter = express.Router()
  apiSpecRouter.use('/ui', swaggerUI.serve, swaggerUI.setup(openapiSpec))
  apiSpecRouter.get('/openapi.json', (req: express.Request, res: express.Response) => {
    res.json(openapiSpec)
  })
  app.use('/api-spec', apiSpecRouter)

  // Add routes using openapi validator middleware
  const openApiMiddleware = openapiValidator({
    apiSpec: openapiSpec as any,
    validateResponses: true, // <-- to validate responses
    validateRequests: true, // false by default
    operationHandlers: path.join(__dirname, 'routes')
    // unknownFormats: ['my-format'] // <-- to provide custom formats
    // ignorePaths: /^(?!\/?rp).*$/
  })
  app.use(openApiMiddleware)

  // Add error middleware
  const errorMiddleware: ErrorRequestHandler = (err, req, res, next) => {
    if (err instanceof HttpError || err instanceof WalletError || err instanceof ActionError) {
      const status = Number(err.status ?? 400)
      res.status(status).json({
        code: 1,
        message: err.message
      })
    } else {
      next(err)
    }
  }
  app.use(errorMiddleware)
}
