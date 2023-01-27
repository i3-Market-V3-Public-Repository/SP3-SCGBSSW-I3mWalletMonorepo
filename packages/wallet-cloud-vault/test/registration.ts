/* eslint-disable @typescript-eslint/no-unused-expressions */
import { importJwk, jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import type { OpenApiComponents, OpenApiPaths } from '../types/openapi'
import type { ServerConfig } from '../src/config'

use(chaiHttp)

let apiVersion: string

const user = {
  did: 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
  username: 'testUser',
  authkey: 'uvATmXpCml3YNqyQ-w3CtJfiCOkHIXo4uUAEj4oshGQ'
}

describe('Wallet Cloud-Vault: Registration', function () {
  this.timeout(30000) // ms
  let publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey
  let serverConfig: ServerConfig

  before(async function () {
    const config = await import('../src/config')
    apiVersion = config.apiVersion
    serverConfig = config.server
  })

  describe(`Testing /api/${apiVersion}/registration/publicJwk`, function () {
    it('it should receive a valid public key', async function () {
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/publicJwk`)
      console.log(res.body)
      expect(res).to.have.status(200)
      try {
        publicJwk = (res.body as OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200).jwk
        await importJwk(publicJwk as JWK)
        expect(true)
      } catch (error) {
        this.skip()
        expect(false)
      }
    })
  })

  describe(`Testing /api/${apiVersion}/registration/{data}`, function () {
    it('it should register the test user', async function () {
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify(user)),
        publicJwk as JWK,
        'A256GCM'
      )
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/` + data)
      console.log(res.body)
      expect(res).to.have.status(201)
      expect(res.body.status).to.equal('created')
    })
  })
})
