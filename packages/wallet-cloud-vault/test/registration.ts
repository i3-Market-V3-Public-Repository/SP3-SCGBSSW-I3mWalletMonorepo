/* eslint-disable @typescript-eslint/no-unused-expressions */

import { importJwk, jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { apiVersion, server as serverConfig } from '../src/config'
import { OpenApiComponents, OpenApiPaths } from '../types/openapi'

use(chaiHttp)

describe('Wallet Cloud-Vault: Registration', function () {
  this.timeout(30000) // ms
  let publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey

  describe(`Testing /api/${apiVersion}/registration/publicJwk`, function () {
    it('it should receive a valid public key', async function () {
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/publicJwk`)
      console.log(res.body)
      try {
        publicJwk = (res.body as OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200).jwk
        await importJwk(publicJwk as JWK)
        expect(true)
      } catch (error) {
        expect(false)
      }
    })
  })

  describe(`Testing /api/${apiVersion}/registration/{data}`, function () {
    it('it should register the user', async function () {
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify({
          did: 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
          username: 'testUser',
          authkey: 'uvATmXpCml3YNqyQ-w3CtJfiCOkHIXo4uUAEj4oshGQ'
        })),
        publicJwk as JWK,
        'A256GCM'
      )
      const res = await request(serverConfig.url)
        .get(`/api/${apiVersion}/registration/` + data)
      console.log(res.body)
      expect(res.body.status).to.equal('created')
    })
  })
})
