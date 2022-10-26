/* eslint-disable @typescript-eslint/no-unused-expressions */

import { Veramo, VerifiableCredential } from '@i3m/base-wallet'
import Debug from 'debug'
import { homedir } from 'os'
import { join } from 'path'

import { ServerWallet, serverWalletBuilder } from '#pkg'

const debug = Debug('@i3m/server-wallet:test')

describe('@i3m/server-wallet', function () {
  this.timeout(10000)

  const identities: { [k: string]: string } = {}
  let wallet: ServerWallet
  let veramo: Veramo
  let jwt: string

  before(async function () {
    wallet = await serverWalletBuilder({ password: 'aestqwerwwec42134642ewdqcAADFEe&/1', filepath: join(homedir(), '.server-wallet', 'testStore') })
    veramo = wallet.veramo
  })

  after(async function () {
    await wallet.wipe()
  })

  describe('get DLT provider data', function () {
    it('should get the DLT provider data', async function () {
      const providerData = await wallet.providerinfoGet()
      debug('Provider data:\n' + JSON.stringify(providerData, undefined, 2))
      chai.expect(providerData).to.not.be.undefined
    })
  })

  describe('identities', function () {
    it('should create identities', async function () {
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

    it('Must be able to restore account from private key', async function () {
      const privKey = process.env.PRIVATE_KEY
      if (privKey === undefined) {
        throw new Error('You need to setup a PRIVATE_KEY as an env variable')
      }
      debug('Importing private key: ', privKey.substring(0, 6) + '...')
      await wallet.importDid({
        alias: 'importedKey',
        privateKey: privKey
      })
    })

    it('should list identities', async function () {
      const ddos = await wallet.identityList({})
      debug('List of DIDs: ', ddos)
      chai.expect(ddos.length).to.equal(3)
    })

    it('should generate a signed JWT', async function () {
      const header = { headerField1: 'hello' }
      const payload = { payloadField1: 'yellow', payloadField2: 'brown' }
      jwt = (await wallet.identitySign({ did: identities.alice }, { type: 'JWT', data: { header, payload } })).signature
      chai.expect(jwt).to.not.be.undefined
      debug('generated JWT: ' + jwt)
    })

    it('a JWT with a DID (that is resolved in the connected DLT) as issuer can be verified by the wallet', async function () {
      const verification = await wallet.didJwtVerify({ jwt })
      debug('verification: ' + JSON.stringify(verification, undefined, 2))
      chai.expect(verification.verification).to.equal('success')
    })

    it('verification of the JWT will also succeed if a expected claim is found in the payload', async function () {
      const verification = await wallet.didJwtVerify({
        jwt,
        expectedPayloadClaims: {
          payloadField1: 'yellow',
          payloadField2: ''
        }
      })
      debug('verification: ' + JSON.stringify(verification, undefined, 2))
      chai.expect(verification.verification).to.equal('success')
    })

    it('verification of the JWT will fail if a expected claim is not in the payload', async function () {
      const verification = await wallet.didJwtVerify({
        jwt,
        expectedPayloadClaims: {
          noneExistingField: ''
        }
      })
      debug('verification: ' + JSON.stringify(verification, undefined, 2))
      chai.expect(verification.verification).to.equal('failed')
    })

    it('verification of the JWT will fail if the signature is invalid', async function () {
      const verification = await wallet.didJwtVerify({
        jwt: jwt.slice(0, -10) + 'aAbBcCdDeE'
      })
      debug('verification: ' + JSON.stringify(verification, undefined, 2))
      chai.expect(verification.verification).to.equal('failed')
    })
  })

  describe('verifiable credentials', function () {
    let credential: VerifiableCredential

    before(async function () {
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

    it('should store verifiable credentials', async function () {
      const resource = await wallet.resourceCreate({
        type: 'VerifiableCredential',
        resource: credential
      })
      debug('Resource with id: ', resource.id)
      chai.expect(resource.id).to.not.be.undefined
    })

    it('should list created resources', async function () {
      const resources = await wallet.resourceList({
        type: 'VerifiableCredential',
        identity: identities.alice
      })
      chai.expect(resources.length).to.equal(1)
    })
  })

  describe('verifiable credentials', function () {
    let credential: VerifiableCredential

    before(async function () {
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

    it('should store verifiable credentials', async function () {
      const resource = await wallet.resourceCreate({
        type: 'VerifiableCredential',
        resource: credential
      })
      debug('Resource with id: ', resource.id)
      chai.expect(resource.id).to.not.be.undefined
    })

    it('should list created resources', async function () {
      const resources = await wallet.resourceList({
        type: 'VerifiableCredential',
        identity: identities.alice
      })
      chai.expect(resources.length).to.equal(1)
    })
  })
  
  describe('selectiveDisclosure', function () {
    let sdrRespJwt: string
    let sdr: string

    before(async function () {
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

    it('should resolve selective disclosure requests', async function () {
      const dialog = wallet.dialog
      await dialog.setValues({
        // Select dispacth claim with the last identity
        // The first one is cancel
        selectMap (values: any[]) {
          return values[values.length - 1]
        }
      }, async function () {
        const sdrResp = await wallet.selectiveDisclosure({ jwt: sdr })
        sdrRespJwt = sdrResp.jwt as string
        chai.expect(sdrRespJwt).to.not.be.undefined
        debug('Selective Disclosure Response:', sdrResp)
      })
    })

    it('should respond with a proper signature', async function () {
      await veramo.agent.handleMessage({
        raw: sdrRespJwt
      })
    })
  })
})
