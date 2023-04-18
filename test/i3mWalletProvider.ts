/* eslint-disable @typescript-eslint/no-unused-expressions */

import * as _pkg from '#pkg'
import type { ServerWallet } from '@i3m/server-wallet'
import { WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { WalletApi } from '@i3m/wallet-protocol-api'
import { randBytes } from 'bigint-crypto-utils'
import { expect } from 'chai'
import { ethers } from 'ethers'
import { hashable } from 'object-sha'

const sessionObjJson = process.env.I3M_WALLET_SESSION_TOKEN as string

if (IS_BROWSER) {
  console.log('This test is not executed in a browser (server wallet only works on node). Skipping')
} else if (sessionObjJson === undefined) {
  console.log(`Skipping test.
You need to pass a I3M_WALLET_SESSION_TOKEN as env variable.
Steps for creating a token:
 - Set your wallet in pairing mode. A PIN appears in the screen
 - Connect to http://localhost:29170/pairing
 - If session is ON, click "Remove session"
 - Click "Start protocol" and fill in the PIN when requested.
 - After succesful pairing, click "Session to clipboard"
 - Edit your .env file or add a new environment variable in you CI provider with key I3M_WALLET_SESSION_TOKEN and value the pasted contents`)
} else {
  describe('A complete secure data exchange flow with NRP. A provider using the I3M-Wallet deskptop application, and the consumer using the server wallet', function () {
    this.timeout(2000000)
    this.bail() // stop after a test fails

    const sessionObj = JSON.parse(sessionObjJson)

    const dids: { [k: string]: string } = {}

    let providerWallet: WalletApi
    let consumerWallet: ServerWallet
    let providerOperatorWallet: ServerWallet

    let dataSharingAgreement: WalletComponents.Schemas.DataSharingAgreement

    let join, homedir, serverWalletBuilder, rmSync

    before(async function () {
      join = (await import('path')).join
      homedir = (await import('os')).homedir
      serverWalletBuilder = (await import('@i3m/server-wallet')).serverWalletBuilder
      rmSync = (await import('fs')).rmSync

      // Setup provider wallet
      const transport = new HttpInitiatorTransport()
      const session = await Session.fromJSON(transport, sessionObj)
      providerWallet = new WalletApi(session)

      // Setup provider operator wallet
      const providerOperatorStoreFilePath = join(homedir(), '.server-wallet', '_test_providerOperator')
      try {
        rmSync(providerOperatorStoreFilePath)
      } catch (error) {}
      providerOperatorWallet = await serverWalletBuilder({ password: 'qwertqwe1234542134642ewdqcAADFEe&/1', reset: true, filepath: providerOperatorStoreFilePath })

      // Setup consumer wallet
      const consumerStoreFilePath = join(homedir(), '.server-wallet', '_test_consumer')
      try {
        rmSync(consumerStoreFilePath)
      } catch (error) {}
      consumerWallet = await serverWalletBuilder({ password: '4e154asdrwwec42134642ewdqcADFEe&/1', reset: true, filepath: consumerStoreFilePath })
    })

    describe('setup identities for the NRP', function () {
      before('should find the provider identity (which should have funds) already imported in the wallet (use a BOK wallet)', async function () {
        // Import provider identity (it has funds to operate with the DLT)
        const privateKey = process.env.PRIVATE_KEY
        if (privateKey === undefined) {
          throw new Error('You need to pass a PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
        }
        const privateKeyHex = _pkg.parseHex(privateKey, true)
        const publicKeyHex = ethers.utils.computePublicKey(privateKeyHex)
        const compressedPublicKey = ethers.utils.computePublicKey(publicKeyHex, true)
        const did = `did:ethr:i3m:${compressedPublicKey}`

        const resp = await providerWallet.identities.info({ did })
        if (resp.addresses !== undefined && resp.addresses.length === 0) {
          throw new Error('You have to import your PRIVATE_KEY to your wallet. Currently, the only way is to setup the wallet as a BOK (bag of keys) one')
        }
        dids.provider = did
        console.log(`Provider identity found: ${did}`)
      })
      it('should create a new identity for the provider operator (who signs the data sharing agreement)', async function () {
        // Create an identity for the consumer
        const resp = await providerOperatorWallet.identityCreate({
          alias: 'provider'
        })
        chai.expect(resp.did).to.not.be.empty
        dids.providerOperator = resp.did
        console.log(`New provider operator identity created for the tests: ${resp.did}`)
      })
      it('should create a new identity for the consumer', async function () {
        // Create an identity for the consumer
        const resp = await consumerWallet.identityCreate({
          alias: 'B'
        })
        chai.expect(resp.did).to.not.be.empty
        dids.consumer = resp.did
        console.log(`New consumer identity created for the tests: ${resp.did}`)
      })
    })

    describe('NRP', function () {
      this.bail() // stop after a test fails

      let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
      let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest

      let providerWalletAgent: _pkg.I3mWalletAgentOrig
      let consumerWalletAgent: _pkg.I3mServerWalletAgentDest

      before('should prepare agents and check that the provider one has funds to interact with the DLT', async function () {
        // Prepare consumer agent
        consumerWalletAgent = new _pkg.I3mServerWalletAgentDest(consumerWallet, dids.consumer)

        // Prepare provider agent
        providerWalletAgent = new _pkg.I3mWalletAgentOrig(providerWallet, dids.provider)

        const providerLedgerAddress = await providerWalletAgent.getAddress()
        console.log(`Provider ledger address: ${providerLedgerAddress}`)

        const providerBalance = await providerWalletAgent.provider.getBalance(providerLedgerAddress)
        console.log(`Provider balance: ${providerBalance.toString()}`)

        expect(providerBalance.toBigInt() > 50000000000000n).to.be.true
      })

      it('should prepare and store in the wallets a valid data sharing agreeemt', async function () {
        // Create a random block of data for the data exchange
        const block = new Uint8Array(await randBytes(256))

        // Create random fresh keys for the data exchange
        const consumerJwks = await _pkg.generateKeys('ES256')
        const providerJwks = await _pkg.generateKeys('ES256')

        // Prepare the data sharing agreeement
        dataSharingAgreement = (await import('./dataSharingAgreementTemplate.json')).default as WalletComponents.Schemas.DataSharingAgreement

        const dataExchangeAgreement: _pkg.DataExchangeAgreement = {
          ...dataSharingAgreement.dataExchangeAgreement,
          orig: await _pkg.parseJwk(providerJwks.publicJwk, true),
          dest: await _pkg.parseJwk(consumerJwks.publicJwk, true),
          encAlg: 'A256GCM',
          signingAlg: 'ES256',
          hashAlg: 'SHA-256',
          ledgerSignerAddress: await providerWalletAgent.getAddress()
        }

        dataSharingAgreement.dataExchangeAgreement = dataExchangeAgreement

        const { signatures, ...payload } = dataSharingAgreement

        dataSharingAgreement.parties.providerDid = dids.providerOperator
        dataSharingAgreement.parties.consumerDid = dids.consumer

        dataSharingAgreement.signatures.providerSignature = (await providerOperatorWallet.identitySign({ did: dids.providerOperator }, { type: 'JWT', data: { payload } })).signature
        dataSharingAgreement.signatures.consumerSignature = (await consumerWallet.identitySign({ did: dids.consumer }, { type: 'JWT', data: { payload } })).signature

        console.log(dataSharingAgreement)

        // provider stores agreement
        const resource = await providerWallet.resources.create({
          type: 'Contract',
          resource: {
            dataSharingAgreement,
            keyPair: {
              publicJwk: await _pkg.parseJwk(providerJwks.publicJwk, true),
              privateJwk: await _pkg.parseJwk(providerJwks.privateJwk, true)
            }
          }
        })
        console.log('Provider stores data sharing agreement with id: ', resource.id)
        chai.expect(resource.id).to.not.be.undefined

        // consumer stores agreement
        const resource2 = await consumerWallet.resourceCreate({
          type: 'Contract',
          identity: dids.consumer,
          resource: {
            dataSharingAgreement,
            keyPair: {
              publicJwk: await _pkg.parseJwk(consumerJwks.publicJwk, true),
              privateJwk: await _pkg.parseJwk(consumerJwks.privateJwk, true)
            }
          }
        })
        console.log('Consumer stores data sharing agreement with id: ', resource2.id)
        chai.expect(resource2.id).to.not.be.undefined

        expect(resource.id).to.be.equal(resource2.id)

        // Ready for starting the NRP
        nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerWalletAgent)
        nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerWalletAgent)
      })

      describe('create/verify proof of origin (PoO)', function () {
        let poo: _pkg.StoredProof<_pkg.PoOPayload>
        this.beforeAll(async function () {
          poo = await nrpProvider.generatePoO()
        })
        it('provider should create a valid signed PoO that is properly verified by the consumer', async function () {
          const verification = await nrpConsumer.verifyPoO(poo.jws, nrpProvider.block.jwe)
          chai.expect(verification).to.not.equal(undefined)
        })
        it('provider stores PoO in wallet', async function () {
          const resource = await providerWallet.resources.create({
            type: 'NonRepudiationProof',
            resource: poo.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoO in wallet', async function () {
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            resource: poo.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
      })

      describe('create/verify proof of reception (PoR)', function () {
        let por: _pkg.StoredProof<_pkg.PoRPayload>
        this.beforeAll(async function () {
          por = await nrpConsumer.generatePoR()
        })
        it('consumer should create a valid signed PoR that is properly verified by the provider', async function () {
          const verification = await nrpProvider.verifyPoR(por.jws)
          chai.expect(verification).to.not.equal(undefined)
        })
        it('provider stores PoR in wallet', async function () {
          const resource = await providerWallet.resources.create({
            type: 'NonRepudiationProof',
            resource: por.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoR in wallet', async function () {
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            resource: por.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
      })

      describe('create/verify proof of publication (PoP)', function () {
        this.timeout(120000)
        let pop: _pkg.StoredProof<_pkg.PoPPayload>
        before(async function () {
          pop = await nrpProvider.generatePoP()
        })
        it('provider should create a valid signed PoP that is properly verified by the consumer', async function () {
          const verified = await nrpConsumer.verifyPoP(pop.jws)
          console.log(JSON.stringify(verified.payload, undefined, 2))
          chai.expect(verified).to.not.equal(undefined)
        })
        it('provider stores PoP in wallet', async function () {
          const resource = await providerWallet.resources.create({
            type: 'NonRepudiationProof',
            resource: pop.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoP in wallet', async function () {
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            resource: pop.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
      })

      describe('decrypt and verify decrypted cipherblock', function () {
        it('consumer should be able to decrypt and hash(decrypted block) should be equal to the dataExchange.blockCommitment', async function () {
          const decryptedBlock = await nrpConsumer.decrypt()
          chai.expect(hashable(nrpProvider.block.raw)).to.equal((decryptedBlock !== undefined) ? hashable(decryptedBlock) : '')
        })
      })

      describe('get secret from ledger', function () {
        const timeout = 180000 // 3 minutes (we currently have one block every 2 minutes)
        this.timeout(timeout)
        it('should be the same secret as the one obtained in the PoP', async function () {
          const secret = { ...nrpConsumer.block.secret }
          const secretFromLedger = await nrpConsumer.getSecretFromLedger()
          chai.expect(hashable(secret)).to.equal(hashable(secretFromLedger))
          nrpConsumer.block.secret = secret as _pkg.Block['secret']
        })
      })
    })
  })
}
