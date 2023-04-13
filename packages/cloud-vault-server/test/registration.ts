/* eslint-disable @typescript-eslint/no-unused-expressions */
import { importJwk, jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import type { OpenApiComponents, OpenApiPaths } from '../types/openapi'
import type { ServerConfig } from '../src/config'

use(chaiHttp)

let apiVersion: string

const user = {
  did: process.env.TEST_DID,
  username: 'testUser',
  authkey: 'uvATmXpCml3YNqyQ-w3CtJfiCOkHIXo4uUAEj4oshGQ'
}

describe('Wallet Cloud-Vault: Registration', function () {
  this.timeout(30000) // ms
  let publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey
  let serverConfig: ServerConfig
  let wellKnownCvsConfiguration: OpenApiComponents.Schemas.CvsConfiguration

  before(async function () {
    const config = await import('../src/config')
    apiVersion = config.apiVersion
    serverConfig = config.serverConfig
    const res = await request(serverConfig.publicUrl)
      .get('/.well-known/cvs-configuration')
    expect(res).to.have.status(200)
    wellKnownCvsConfiguration = res.body
  })

  describe(`Testing /api/${apiVersion}/registration/public-jwk`, function () {
    it('it should receive a valid public key', async function () {
      const url = new URL(wellKnownCvsConfiguration.registration_configuration.public_jwk_endpoint)
      const res = await request(url.origin)
        .get(url.pathname + url.search + url.hash)
      console.log(res.body)
      expect(res).to.have.status(200)
      try {
        publicJwk = (res.body as OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200).jwk
        await importJwk(publicJwk as JWK)
        expect(true)
      } catch (error) {
        this.skip()
      }
    })
  })

  describe(`Testing /api/${apiVersion}/registration/register/{data}`, function () {
    it('should create a valid registration link', async function () {
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify(user)),
        publicJwk as JWK,
        'A256GCM'
      )
      const regLink = wellKnownCvsConfiguration.registration_configuration.registration_endpoint.replace('{data}', data)
      console.log(regLink)
      expect(regLink).to.be.a.string
    })
    // it('should register the test user', async function () {
    //   const data = await jweEncrypt(
    //     Buffer.from(JSON.stringify(user)),
    //     publicJwk as JWK,
    //     'A256GCM'
    //   )
    //   const res = await request(serverConfig.publicUrl)
    //     .get(wellKnownCvsConfiguration.registration_configuration.registration_endpoint.replace('{data}', data))
    //   console.log(res.body)
    //   expect(res).to.have.status(201)
    //   expect(res.body.status).to.equal('created')
    // })
    // it('should fail registering the same user again', async function () {
    //   const data = await jweEncrypt(
    //     Buffer.from(JSON.stringify(user)),
    //     publicJwk as JWK,
    //     'A256GCM'
    //   )
    //   const res = await request(serverConfig.publicUrl)
    //     .get(wellKnownCvsConfiguration.registration_configuration.registration_endpoint.replace('{data}', data))
    //   console.log(res.body)
    //   expect(res).to.not.have.status(201)
    // })
    // it('should deregister the user', async function () {
    //   const res = await request(serverConfig.publicUrl)
    //     .get(wellKnownCvsConfiguration.registration_configuration.deregistration_endpoint)
    //   expect(res).to.have.status(204)
    // })
    // it('since it is deregistered, the test user can be registered again', async function () {
    //   const data = await jweEncrypt(
    //     Buffer.from(JSON.stringify(user)),
    //     publicJwk as JWK,
    //     'A256GCM'
    //   )
    //   const res = await request(serverConfig.publicUrl)
    //     .get(wellKnownCvsConfiguration.registration_configuration.registration_endpoint.replace('{data}', data))
    //   console.log(res.body)
    //   expect(res).to.have.status(201)
    //   expect(res.body.status).to.equal('created')
    // })
  })
})
