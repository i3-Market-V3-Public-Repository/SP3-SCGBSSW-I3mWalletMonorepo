import { Wallet, TestDialog, TestStore, TestToast, Veramo, Resource } from '@i3m/base-wallet'
import Debug from 'debug'

import swBuilder from '..'

const debug = Debug('i3-market:sw-wallet:test')

describe('@i3m/sw-wallet', () => {
  const dialog = new TestDialog()
  const store = new TestStore()
  const toast = new TestToast()
  let wallet: Wallet
  let veramo: Veramo

  const identities: { [k: string]: string } = {}

  beforeAll(async () => {
    // Build the wallet using a valid mnemonic
    await dialog.setValues({
      text: 'zebra jelly kick pattern depth foam enter alone quote seed alpha road ripple enable wheel'
    }, async () => {
      wallet = await swBuilder({ dialog, store, toast })
      veramo = (wallet as any).veramo // TODO: Hacky access to veramo. Maybe expose it?
    })
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
      const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr })
      sdrRespJwt = sdrResp.jwt as string
      expect(sdrRespJwt).toBeDefined()

      debug('Selective Disclosure Response:', sdrResp)
    }, 10000)

    it('should respond with a proper signature', async () => {
      await veramo.agent.handleMessage({
        raw: sdrRespJwt
      })
    })
  })
})
