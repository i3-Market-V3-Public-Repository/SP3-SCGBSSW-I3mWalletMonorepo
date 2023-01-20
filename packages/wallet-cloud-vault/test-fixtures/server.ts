import { Server } from 'http'
import serverPromise from '../src'

let server: Server

before(async () => {
  server = await serverPromise
})

after(done => {
  server.close((err) => {
    done(err)
  })
})
