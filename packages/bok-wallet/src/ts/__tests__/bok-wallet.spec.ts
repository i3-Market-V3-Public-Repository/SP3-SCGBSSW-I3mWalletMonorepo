/* eslint-disable @typescript-eslint/no-unused-expressions */

import { Wallet, NullDialog, RamStore, ConsoleToast, Veramo, VerifiableCredential } from '@i3m/base-wallet'
import Debug from 'debug'

import swBuilder from '#pkg'

const debug = Debug('i3-market:bok-wallet:test')

describe('@i3m/sw-wallet', () => {
  const dialog = new NullDialog()
  const store = new RamStore()
  const toast = new ConsoleToast()
  let wallet: Wallet
  let veramo: Veramo

  const identities: { [k: string]: string } = {}

  before(async () => {
    // Build the wallet using a valid mnemonic
    await dialog.setValues({
      text: 'zebra jelly kick pattern depth foam enter alone quote seed alpha road ripple enable wheel'
    }, async () => {
      wallet = await swBuilder({ dialog, store, toast })
      veramo = (wallet as any).veramo // TODO: Hacky access to veramo. Maybe expose it?
    })
  })

  describe('identities', () => {
    it('should create identities', async () => {
      const resp = await wallet.identityCreate({
        alias: 'alice'
      })
      chai.expect(resp.did).to.not.be.empty // eslint-disable-line

      identities.alice = resp.did
      debug('DID for \'alice\' created: ', resp.did)

      const resp2 = await wallet.identityCreate({
        alias: 'bob'
      })
      chai.expect(resp2.did).to.not.be.empty

      identities.bob = resp.did
      debug('DID for \'bob\' created: ', resp2.did)
    })

    it('should list identities', async () => {
      const ddos = await wallet.identityList({})
      debug('List of DIDs: ', ddos)
      chai.expect(ddos.length).to.equal(2)
    })
  })

  describe('resources', () => {
    let credential: VerifiableCredential

    before(async () => {
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
      }) as VerifiableCredential // TODO: Force type.
    })

    it('should store verifiable credentials', async () => {
      const resource = await wallet.resourceCreate({
        type: 'VerifiableCredential',
        resource: credential
      })

      debug('Resource with id: ', resource.id)
      chai.expect(resource.id).to.not.be.undefined
    })

    it('should list created resources', async () => {
      const resources = await wallet.resourceList({
        type: 'VerifiableCredential',
        identity: identities.alice
      })
      chai.expect(resources.length).to.equal(1)
    })
  })

  describe('selectiveDisclosure', () => {
    let sdrRespJwt: string
    let sdr: string

    before(async () => {
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
      await dialog.setValues({
        // Select dispacth claim with the last identity
        // The first one is cancel
        selectMap (values) {
          return values[values.length - 1]
        }
      }, async () => {
        const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr })
        sdrRespJwt = sdrResp.jwt as string
        chai.expect(sdrRespJwt).to.not.be.undefined
        debug('Selective Disclosure Response:', sdrResp)
      })
    })

    it('should respond with a proper signature', async () => {
      await veramo.agent.handleMessage({
        raw: sdrRespJwt
      })
    })
  })
})
