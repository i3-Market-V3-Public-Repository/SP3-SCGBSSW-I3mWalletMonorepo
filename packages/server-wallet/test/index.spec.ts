import { Veramo, Resource, Wallet } from '@i3m/base-wallet'
import Debug from 'debug'

import { serverWalletBuilder } from '../src'

const debug = Debug('@i3m/server-wallet:test')

describe('@i3m/server-wallet', () => {
  const identities: { [k: string]: string } = {}
  let wallet: Wallet
  let veramo: Veramo

  beforeAll(async () => {
    wallet = await serverWalletBuilder()
  })

  describe('identities', () => {
    it.each([
      ['alice'],
      ['bob']
    ])('should create identities', async (alias) => {
      const resp = await wallet.identityCreate({
        alias
      })
      expect(resp.did).toBeDefined()

      identities[alias] = resp.did
      debug(`DID for '${alias}' created: `, resp.did)
    })

    it('should list identities', async () => {
      const ddos = await wallet.identityList({})
      debug('List of DIDs: ', ddos)
      expect(ddos.length).toBe(2)
    })
  })

  describe('resources', () => {
    let credential: Resource['resource']

    beforeAll(async () => {
      credential = await veramo.agent.createVerifiableCredential({
        credential: {
          issuer: { id: identities.bob },
          credentialSubject: {
            id: identities.alice,
            consumer: true
          }
        },
        proofFormat: 'jwt',
        save: false
      }) as Resource['resource'] // TODO: Force type.
    })

    it('should store verifiable credentials', async () => {
      const resource = await wallet.resourceCreate({
        type: 'VerifiableCredential',
        resource: credential
      })

      debug('Resource with id: ', resource.id)
      expect(resource.id).toBeDefined()
    })

    it('should list created resources', async () => {
      const resources = await wallet.resourceList()
      expect(resources.length).toBe(1)
    })
  })

  // describe('selectiveDisclosure', () => {
  //   let sdrRespJwt: string
  //   let sdr: string

  //   beforeAll(async () => {
  //     // Generate a sdr generated on the fly
  //     sdr = await veramo.agent.createSelectiveDisclosureRequest({
  //       data: {
  //         issuer: identities.bob,
  //         claims: [{
  //           claimType: 'consumer'
  //         }]
  //       }
  //     })
  //   })

  //   it('should resolve selective disclosure requests', async () => {
  //     await dialog.setValues({
  //       // Select dispacth claim with the last identity
  //       // The first one is cancel
  //       selectMap (values) {
  //         return values[values.length - 1]
  //       }
  //     }, async () => {
  //       const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr })
  //       sdrRespJwt = sdrResp.jwt as string
  //       expect(sdrRespJwt).toBeDefined()
  //       debug('Selective Disclosure Response:', sdrResp)
  //     })
  //   }, 10000)

  //   it('should respond with a proper signature', async () => {
  //     await veramo.agent.handleMessage({
  //       raw: sdrRespJwt
  //     })
  //   })
  // })
})
