/* eslint-disable @typescript-eslint/no-unused-expressions */

import { randBytes } from 'bigint-crypto-utils'
import { hashable } from 'object-sha'
import { ServerWallet } from '@i3m/server-wallet/types'
import { WalletComponents } from '@i3m/wallet-desktop-openapi/types'
import * as _pkg from '#pkg'
import { expect } from 'chai'
import { DataExchangeAgreement } from '#pkg'

if (!IS_BROWSER) {
  describe('testing signing transactions with i3M-ServerWallet', function () {
    this.timeout(2000000)
    this.bail() // stop after a test fails

    const dids: { [k: string]: string } = {}

    let providerWallet: ServerWallet
    let consumerWallet: ServerWallet

    let dataSharingAgreement: WalletComponents.Schemas.Contract['resource']

    let join, homedir, serverWalletBuilder, rmSync

    before(async function () {
      join = (await import('path')).join
      homedir = (await import('os')).homedir
      serverWalletBuilder = (await import('@i3m/server-wallet')).serverWalletBuilder
      rmSync = (await import('fs')).rmSync

      // Setup provider wallet
      const providerStoreFilePath = join(homedir(), '.server-wallet', '_test_provider')
      try {
        rmSync(providerStoreFilePath)
      } catch (error) {}
      providerWallet = await serverWalletBuilder({ password: 'aestqwerwwec42134642ewdqcAADFEe&/1', reset: true, filepath: providerStoreFilePath })

      // Setup consumer wallet
      const consumerStoreFilePath = join(homedir(), '.server-wallet', '_test_consumer')
      try {
        rmSync(consumerStoreFilePath)
      } catch (error) {}
      consumerWallet = await serverWalletBuilder({ password: '4e154asdrwwec42134642ewdqcADFEe&/1', reset: true, filepath: consumerStoreFilePath })
    })

    describe('create identities for the NRP', function () {
      it('should import the provider identity (which should have funds)', async function () {
        // Import provider identity (it has funds to operate with the DLT)
        const privateKey = process.env.PRIVATE_KEY
        if (privateKey === undefined) {
          throw new Error('You need to pass a PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
        }
        await providerWallet.importDid({
          alias: 'provider',
          privateKey
        })
        const availableIdentities = await providerWallet.identityList({ alias: 'provider' })
        const identity = availableIdentities[0]

        chai.expect(identity.did).to.not.be.empty

        dids.provider = identity.did
        console.log(`New provider identity created for the tests: ${identity.did}`)
      })
      it('should create a new identity for the consumer', async function () {
        // Create an identity for the consumer
        const resp = await consumerWallet.identityCreate({
          alias: 'consumer'
        })
        chai.expect(resp.did).to.not.be.empty
        dids.consumer = resp.did
        console.log(`New consumer identity created for the tests: ${resp.did}`)
      })
    })

    describe('NRP', function () {
      let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
      let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest

      let providerWalletAgent: _pkg.I3mServerWalletAgentOrig
      let consumerWalletAgent: _pkg.I3mServerWalletAgentDest

      before('should prepare agents and check that the provider one has funds to interact with the DLT', async function () {
        // Prepare consumer agent
        consumerWalletAgent = new _pkg.I3mServerWalletAgentDest(consumerWallet, dids.consumer)

        // Prepare provider agent
        providerWalletAgent = new _pkg.I3mServerWalletAgentOrig(providerWallet, dids.provider)

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
        dataSharingAgreement = (await import('./dataSharingAgreementTemplate.json')).default as WalletComponents.Schemas.Contract['resource']
        dataSharingAgreement.parties.providerDid = dids.provider
        dataSharingAgreement.parties.consumerDid = dids.consumer

        const dataExchangeAgreement: DataExchangeAgreement = {
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

        dataSharingAgreement.signatures.providerSignature = (await providerWallet.identitySign({ did: dids.provider }, { type: 'JWT', data: { payload } })).signature

        dataSharingAgreement.signatures.consumerSignature = (await consumerWallet.identitySign({ did: dids.consumer }, { type: 'JWT', data: { payload } })).signature

        console.log(dataSharingAgreement)

        // provider stores agreement
        const resource = await providerWallet.resourceCreate({
          type: 'Contract',
          identity: dids.provider,
          resource: dataSharingAgreement
        })
        console.log('Provider stores data sharing agreement with id: ', resource.id)
        chai.expect(resource.id).to.not.be.undefined

        // consumer stores agreement
        const resource2 = await consumerWallet.resourceCreate({
          type: 'Contract',
          identity: dids.consumer,
          resource: dataSharingAgreement
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
          const resource = await providerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.provider,
            resource: poo.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoO in wallet', async function () {
          // consumer stores agreement
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.consumer,
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
          const resource = await providerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.provider,
            resource: por.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoR in wallet', async function () {
          // consumer stores agreement
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.consumer,
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
          const resource = await providerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.provider,
            resource: pop.jws
          })
          chai.expect(resource.id).to.not.be.undefined
        })
        it('consumer stores PoP in wallet', async function () {
          // consumer stores agreement
          const resource = await consumerWallet.resourceCreate({
            type: 'NonRepudiationProof',
            identity: dids.consumer,
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
