/* eslint-disable @typescript-eslint/no-unused-expressions */

import { importJwk, JWK } from '@i3m/non-repudiation-library'
import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { Server } from 'http'
import serverPromise from '../src'
import { server as serverConfig, apiVersion } from '../src/config'
import { OpenApiPaths } from '../types/openapi'

use(chaiHttp)

describe('Wallet Cloud-Vault: Registration', function () {
  this.timeout(20000) // ms

  let server: Server

  before(async () => {
    server = await serverPromise
  })

  after((done) => {
    server.close((err) => {
      done(err)
    })
  })

  describe(`Testing /api/${apiVersion}/registration/publicJwk`, function () {
    it('it should receive a string', async function () {
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/publicJwk`)
      console.log(res.body)
      try {
        await importJwk((res.body as OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200).jwk as JWK)
        expect(true)
      } catch (error) {
        expect(false)
      }
    })
  })

  describe(`Testing /api/${apiVersion}/registration/{data}`, function () {
    it('it should register the user', async function () {
      const data = 'dasfsdaf32'
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/` + data)
      console.log(res.body)
      expect(res.body.status).to.equal('created')
    })
  })
})
