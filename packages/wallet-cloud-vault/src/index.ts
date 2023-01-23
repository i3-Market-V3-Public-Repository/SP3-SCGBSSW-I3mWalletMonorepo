#!/usr/bin/env node
import express, { Express } from 'express'
import http from 'http'
import morgan from 'morgan'
import { server as serverConfig, general } from './config'
import apiRoutesPromise from './routes/api'
import oasRoutesPromise from './routes/oas'

async function startApp (): Promise<Express> {
  const app = express()
  app.use(express.json())
  app.use(morgan(general.nodeEnv === 'development' ? 'dev' : 'tiny'))

  // Load CORS for the routes
  app.use((await import('./middlewares/cors')).corsMiddleware)

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

const serverPromise = new Promise<http.Server>((resolve, reject) => {
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
      // console.log(`OpenAPI JSON spec at ${publicUri}/openapi.json`)
      // console.log(`OpenAPI browsable spec at ${publicUri}/spec`)
      resolve(server)
    })
  }).catch((e) => {
    console.log(e)
    reject(e)
  })
})

export default serverPromise
