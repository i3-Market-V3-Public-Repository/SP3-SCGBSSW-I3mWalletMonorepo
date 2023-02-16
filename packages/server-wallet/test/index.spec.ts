/* eslint-disable @typescript-eslint/no-unused-expressions */

import { VerifiableCredential } from '@i3m/base-wallet'
import { generateKeys, parseJwk } from '@i3m/non-repudiation-library'
import { WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import Debug from 'debug'
import { homedir } from 'os'
import { join } from 'path'

import { ServerWallet, serverWalletBuilder } from '#pkg'

const debug = Debug('@i3m/server-wallet:test')

describe('@i3m/server-wallet', function () {
  this.timeout(60000)

  const identities: { [k: string]: string } = {}
  let wallet: ServerWallet
  let jwt: string

  before(async function () {
    wallet = await serverWalletBuilder({
      password: 'aestqwerwwec42134642ewdqcAADFEe&/1',
      reset: true,
      filepath: join(homedir(), '.server-wallet', 'testStore')
      // provider: 'did:ethr:i3m',
      // providerData: {
      //   'did:ethr:i3m': {
      //     network: 'i3m',
      //     // rpcUrl: ['http://95.211.3.249:8545', 'http://95.211.3.250:8545']
      //     // rpcUrl: ['http://95.215.3.249:8545', 'http://87.211.3.249:8545', 'http://95.211.3.249:8545', 'http://95.211.3.250:8545'] // the two first are not RPC endpoints
      //     rpcUrl: ['http://95.215.3.249:8545', 'http://87.211.3.249:8545', 'http://95.211.3.249:8545'] // the two first are not RPC endpoints
      //   }
      // }
    })
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
      chai.expect(resp.did).to.not.be.empty

      identities.alice = resp.did
      debug('DID for \'alice\' created: ', resp.did)

      const resp2 = await wallet.identityCreate({
        alias: 'bob'
      })
      chai.expect(resp2.did).to.not.be.empty

      identities.bob = resp2.did
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
          payloadField1: 'yellow'
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
      credential = await wallet.veramo.agent.createVerifiableCredential({
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
      debug('Resources: ', JSON.stringify(resources, undefined, 2))
      chai.expect(resources.length).to.equal(1)
    })
  })

  describe('data sharing agreeements', function () {
    let dataSharingAgreement: WalletComponents.Schemas.DataSharingAgreement
    let keyPair: {
      publicJwk: string
      privateJwk: string
    }

    before(async function () {
      dataSharingAgreement = (await import('./dataSharingAgreementTemplate.json')).default as WalletComponents.Schemas.DataSharingAgreement

      dataSharingAgreement.parties.providerDid = identities.alice
      dataSharingAgreement.parties.consumerDid = identities.bob

      const addresses = (await wallet.identityInfo({ did: identities.alice })).addresses
      dataSharingAgreement.dataExchangeAgreement.ledgerSignerAddress = ((addresses != null) && addresses.length > 0) ? addresses[0] : ''

      const jwkPair = await generateKeys(dataSharingAgreement.dataExchangeAgreement.signingAlg)
      keyPair = {
        privateJwk: await parseJwk(jwkPair.privateJwk, true),
        publicJwk: await parseJwk(jwkPair.publicJwk, true)
      }
      dataSharingAgreement.dataExchangeAgreement.orig = keyPair.publicJwk

      const { signatures, ...payload } = dataSharingAgreement

      dataSharingAgreement.signatures.providerSignature = (await wallet.identitySign({ did: identities.alice }, { type: 'JWT', data: { payload } })).signature

      dataSharingAgreement.signatures.consumerSignature = (await wallet.identitySign({ did: identities.bob }, { type: 'JWT', data: { payload } })).signature

      debug(keyPair)

      debug(dataSharingAgreement)
    })

    it('should store a data sharing agreement', async function () {
      const resource = await wallet.resourceCreate({
        type: 'Contract',
        identity: identities.alice,
        resource: {
          dataSharingAgreement,
          keyPair
        }
      })
      debug('Resource with id: ', resource.id)
      chai.expect(resource.id).to.not.be.undefined
    })

    it('should not allow to store a data sharing agreement if the provided keyPair is not part of the exchange agreeement', async function () {
      const dataSharingAgreementResource: WalletComponents.Schemas.Contract = {
        type: 'Contract',
        identity: identities.alice,
        resource: {
          dataSharingAgreement: { ...dataSharingAgreement, parties: { providerDid: 'sdaf', consumerDid: '' } },
          keyPair
        }
      }
      let error: Error = new Error('')
      try {
        await wallet.resourceCreate(dataSharingAgreementResource)
      } catch (err) {
        error = err as Error
        debug('Resource not created: ', JSON.stringify(error, undefined, 2))
      }

      chai.expect(error.message).to.not.equal('')
    })

    it('should not allow to store an invalid data sharing agreement', async function () {
      const dataSharingAgreementResource: WalletComponents.Schemas.Contract = {
        type: 'Contract',
        identity: identities.alice,
        resource: {
          dataSharingAgreement: { ...dataSharingAgreement, parties: { providerDid: 'sdaf', consumerDid: '' } },
          keyPair
        }
      }
      let error: Error = new Error('')
      try {
        await wallet.resourceCreate(dataSharingAgreementResource)
      } catch (err) {
        error = err as Error
        debug('Resource not created: ', JSON.stringify(error, undefined, 2))
      }

      chai.expect(error.message).to.not.equal('')
    })

    it('should list stored data sharing agreements', async function () {
      const resources = await wallet.resourceList({
        type: 'Contract',
        identity: identities.alice
      })
      debug('Resources: ', JSON.stringify(resources, undefined, 2))
      chai.expect(resources.length).to.equal(1)
    })
  })

  describe('selectiveDisclosure', function () {
    let sdrRespJwt: string
    let sdr: string

    before(async function () {
      // Generate a sdr generated on the fly
      sdr = await wallet.veramo.agent.createSelectiveDisclosureRequest({
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
      await wallet.veramo.agent.handleMessage({
        raw: sdrRespJwt
      })
    })
  })
})
