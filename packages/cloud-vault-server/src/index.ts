#!/usr/bin/env node
import express, { Express } from 'express'
import http from 'http'
import morgan from 'morgan'
import { general, server as serverConfig, dbConfig } from './config'
import apiRoutesPromise from './routes/api'
import oasRoutesPromise from './routes/oas'
import wellKnownCvsConfigurationRoutePromise from './routes/well-known-cvs-configuration'

async function startApp (): Promise<Express> {
  const app = express()
  app.use(express.json({ limit: dbConfig.storageLimit + 1024 }))
  app.use(morgan(general.nodeEnv === 'development' ? 'dev' : 'tiny'))

  // Load CORS for the routes
  app.use((await import('./middlewares/cors')).corsMiddleware)

  // Load the .well-known/cvs-configuration
  app.use('/', await wellKnownCvsConfigurationRoutePromise())

  // OAS routes for downloading OAS json and visulaizing it
  app.use('/', await oasRoutesPromise())

  // Install the OpenApiValidator for the routes
  const apiVersion = 'v' + general.version.split('.')[0]
  app.use('/api/' + apiVersion, (await import('./middlewares/openapi')).openApiValidatorMiddleware)
  // Load API routes
  app.use('/api/' + apiVersion, await apiRoutesPromise())

  // Handle errors
  app.use((await import('./middlewares/error')).errorMiddleware)

  return app
}

export interface Server {
  server: http.Server
  dbConnection: typeof import('./db')
}

const serverPromise = new Promise<Server>((resolve, reject) => {
  let dbConnection: typeof import('./db')
  import('./db').then(module => {
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
    const { port, addr, url } = serverConfig
    server.listen(port, addr)

    /**
      * Event listener for HTTP server "listening" event.
      */
    server.on('listening', function (): void {
      console.log(`⚡️[server]: Server is running at ${url}`)
      console.log(`⚡️[server]: OpenAPI JSON spec at ${url}/spec`)
      console.log(`⚡️[server]: OpenAPI browsable spec at ${url}/spec-ui`)
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

export default serverPromise
export * from './vault'
