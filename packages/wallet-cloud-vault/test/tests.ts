/* eslint-disable @typescript-eslint/no-unused-expressions */

import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { Server } from 'http'
import serverPromise from '../src'
import { server as serverConfig } from '../src/config'
import { OpenApiPaths } from '../types/openapi'

use(chaiHttp)

describe('Conflict-Resolver Service', function () {
  this.timeout(20000) // ms

  let server: Server

  const url = `http://localhost:${serverConfig.port}`

  before(async () => {
    server = await serverPromise
  })

  after((done) => {
    server.close((err) => {
      done(err)
    })
  })

  describe('Testing /publicJwk', function () {
    it('it should receive a string', async function () {
      const res = await request(url)
        .get('/publicJwk')
      console.log(res.body)
      const publicJwk = res.body as OpenApiPaths.PublicJwk.Get.Responses.$200
      expect(publicJwk.publicJwk).to.not.be.undefined
    })
  })
})
