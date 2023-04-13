#!/usr/bin/env node
import crypto from 'crypto'
import express, { Express } from 'express'
import session from 'express-session'
import { readFileSync, writeFileSync } from 'fs'
import http from 'http'
import morgan from 'morgan'
import type { OpenAPIV3 } from 'openapi-types'
import { join as pathJoin } from 'path'
import { apiVersion, dbConfig, general, oidcConfig, serverConfig } from './config'
import apiRoutesPromise from './routes/api'
import oasRoutesPromise from './routes/oas'
import wellKnownCvsConfigurationRoutePromise from './routes/well-known-cvs-configuration'

initSpec()

async function startApp (): Promise<Express> {
  const app = express()

  app.use(session({
    secret: crypto.randomBytes(32).toString('base64'),
    resave: false,
    saveUninitialized: false
  }))

  app.use(express.json({ limit: dbConfig.storageCharLength + 1024 }))
  app.use(morgan(general.nodeEnv === 'development' ? 'dev' : 'tiny'))

  // Load CORS for the routes
  app.use((await import('./middlewares/cors')).corsMiddleware)

  // Load the .well-known/cvs-configuration
  app.use('/', await wellKnownCvsConfigurationRoutePromise())

  // OAS routes for downloading OAS json and visulaizing it
  app.use('/', await oasRoutesPromise())

  // Install the OpenApiValidator for the routes
  app.use('/api/' + apiVersion, (await import('./middlewares/openapi')).openApiValidatorMiddleware)
  // Load API routes
  app.use('/api/' + apiVersion, await apiRoutesPromise())

  // Handle errors
  app.use((await import('./middlewares/error')).errorMiddleware)

  return app
}

export * from './vault'

export interface Server {
  server: http.Server
  dbConnection: typeof import('./db')
}

export const serverPromise = new Promise<Server>((resolve, reject) => {
  let dbConnection: typeof import('./db/index')
  import('./db/index').then(module => {
    dbConnection = module
    dbConnection.db.initialized.then(() => {
      console.log('⚡️[server]: DB connection ready')
    }).catch((error) => {
      throw new Error('DB connection failed\n' + JSON.stringify(error, undefined, 2))
    })
  }).catch((err) => {
    reject(err)
  })

  startApp().then((app) => {
    /**
     * Listen on .env SERVER_PORT or 3000/tcp, on all network interfaces.
     */
    const server = http.createServer(app)
    const { port, addr, publicUrl } = serverConfig

    server.listen(port, addr)

    /**
      * Event listener for HTTP server "listening" event.
      */
    server.on('listening', function (): void {
      console.log(`⚡️[server]: Server is running at ${publicUrl}`)
      console.log(`⚡️[server]: OpenAPI JSON spec at ${publicUrl}/spec`)
      console.log(`⚡️[server]: OpenAPI browsable spec at ${publicUrl}/spec-ui`)
      resolve({ server, dbConnection })
    })

    server.on('close', () => {
      dbConnection.db.close().catch((err) => {
        reject(err)
      })
    })
  }).catch((e) => {
    console.log(e)
    reject(e)
  })
})

function initSpec (): void {
  const oasPath = pathJoin(__dirname, 'spec', 'cvs.json')
  const oas = JSON.parse(readFileSync(oasPath, 'utf8')) as OpenAPIV3.Document
  addServers(oas);
  (oas as any).components.securitySchemes.i3m.openIdConnectUrl = ((oas as any).components.securitySchemes.i3m.openIdConnectUrl as string).replace('OIDC_PROVIDER_URI', oidcConfig.providerUri)
  writeFileSync(oasPath, JSON.stringify(oas, undefined, 2), 'utf-8')
}

function addServers (spec: OpenAPIV3.Document): void {
  const localhostServer: OpenAPIV3.ServerObject = {
    url: serverConfig.localUrl
  }
  spec.servers = [localhostServer]
}
