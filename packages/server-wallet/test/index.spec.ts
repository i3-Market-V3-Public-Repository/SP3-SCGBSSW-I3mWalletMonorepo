import { Veramo, Resource, NullDialog } from '@i3m/base-wallet'
import Debug from 'debug'
import { homedir } from 'os'
import { join } from 'path'
import { verifyJWT } from 'did-jwt'

import { ServerWallet, serverWalletBuilder } from '../src'

const debug = Debug('@i3m/server-wallet:test')

describe('@i3m/server-wallet', () => {
  const identities: { [k: string]: string } = {}
  let wallet: ServerWallet
  let veramo: Veramo

  beforeAll(async () => {
    wallet = await serverWalletBuilder({ password: 'aestqwerwwec42134642ewdqcAADFEe&/1', filepath: join(homedir(), '.server-wallet', 'testStore') })
    veramo = (wallet as any).veramo // TODO: Hacky access to veramo. Maybe expose it?
  })

  afterAll(async () => {
    await wallet.wipe()
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

    it('should generate a signed JWT', async () => {
      const header = { test: 'hola' }
      const payload = { rabo: 'gordo' }
      const { signature } = await wallet.identitySign({ did: identities.alice }, { type: 'JWT', data: { header, payload } })
      expect(signature).toBeDefined()
      debug('generated JWT: ' + signature)
      const resolver = { resolve: (didUrl: string) => veramo.agent.resolveDid({ didUrl }) }
      const verification = await verifyJWT(signature, { resolver })
      debug('JWT verification: ' + JSON.stringify(verification, undefined, 2))
      expect(verification).toBeDefined()
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

  describe('selectiveDisclosure', () => {
    let sdrRespJwt: string
    let sdr: string

    beforeAll(async () => {
      // Generate a sdr generated on the fly
      sdr = await veramo.agent.createSelectiveDisclosureRequest({
        data: {
          issuer: identities.bob,
          claims: [{
            claimType: 'consumer'
          }]
        }
      })
    })

    it('should resolve selective disclosure requests', async () => {
      const dialog = (wallet as any).dialog as NullDialog
      await dialog.setValues({
        // Select dispacth claim with the last identity
        // The first one is cancel
        selectMap (values) {
          return values[values.length - 1]
        }
      }, async () => {
        const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr })
        sdrRespJwt = sdrResp.jwt as string
        expect(sdrRespJwt).toBeDefined()
        debug('Selective Disclosure Response:', sdrResp)
      })
    }, 10000)

    it('should respond with a proper signature', async () => {
      await veramo.agent.handleMessage({
        raw: sdrRespJwt
      })
    })
  })
})
