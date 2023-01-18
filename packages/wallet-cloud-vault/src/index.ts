#!/usr/bin/env node
import express from 'express'
import { Express } from 'express-serve-static-core'
import http from 'http'
import morgan from 'morgan'
import { server as serverConfig } from './config'
import routesPromise from './routes'

function checkIfIPv6 (str: string): boolean {
  const regexExp = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/gi

  return regexExp.test(str)
}

async function startApp (): Promise<Express> {
  const app = express()
  app.use(express.json())
  app.use(morgan('dev'))

  // Load CORS for the routes
  app.use((await import('./middlewares/cors')).corsMiddleware)

  // Install the OpenApiValidator for the routes
  app.use((await import('./middlewares/openapi')).openApiValidatorMiddleware)

  // Load routes
  app.use('/', await routesPromise())

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
    const { port, addr } = serverConfig
    server.listen(port, addr)

    /**
    * Event listener for HTTP server "listening" event.
    */
    server.on('listening', function (): void {
      console.log(`⚡️[server]: Server is running at http://${checkIfIPv6(addr) ? '[' + addr + ']' : addr}:${port}`)
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
