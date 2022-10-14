import { randBytes } from 'bigint-crypto-utils'
import { hashable } from 'object-sha'
import { ServerWallet } from '@i3m/server-wallet/types'
import * as _pkg from '#pkg'

const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

if (!IS_BROWSER) {
  describe('testing signing transactions with i3M-ServerWallet', function () {
    this.timeout(2000000)
    let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
    let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest

    let join, homedir, serverWalletBuilder, rmSync

    this.beforeAll(async function () {
      join = (await import('path')).join
      homedir = (await import('os')).homedir
      serverWalletBuilder = (await import('@i3m/server-wallet')).serverWalletBuilder
      rmSync = (await import('fs')).rmSync

      const storeFile = join(homedir(), '.server-wallet', '_test_providerStore')
      try {
        rmSync(storeFile)
      } catch (error) {}

      const providerWallet: ServerWallet = await serverWalletBuilder({ password: 'aestqwerwwec42134642ewdqcAADFEe&/1', filepath: storeFile })

      const privateKey = process.env.ETHERS_WALLET_PRIVATE_KEY

      if (privateKey === undefined) {
        throw new Error('You need to pass a ETHERS_WALLET_PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
      }

      await providerWallet.importDid({
        alias: '__test__',
        privateKey
      })
      const identities = await providerWallet.identityList({ alias: '__test__' })
      const identity = identities[0]
      console.log(`New identity created for the tests: ${identity.did}`)
      const providerWalletAgent = new _pkg.I3mServerWalletAgentOrig(providerWallet, identity.did)

      const providerLedgerAddress = await providerWalletAgent.getAddress()
      console.log(`Provider ledger address: ${providerLedgerAddress}`)

      const providerBalance = await providerWalletAgent.provider.getBalance(providerLedgerAddress)
      console.log(`Provider balance: ${providerBalance.toString()}`)

      if (providerBalance.toBigInt() < 50000000000000n) {
        throw new Error(`Account ${providerLedgerAddress} does not have enough funds to execute test`)
      }

      const rpcUrl = (await providerWallet.providerinfo()).rpcUrl as string
      const consumerWalletAgent = new _pkg.I3mServerWalletAgentDest({ rpcProviderUrl: rpcUrl })

      const block = new Uint8Array(await randBytes(256))

      const consumerJwks = await _pkg.generateKeys('ES256')
      const providerJwks = await _pkg.generateKeys('ES256')

      const dataExchangeAgreement: _pkg.DataExchangeAgreement = {
        orig: JSON.stringify(providerJwks.publicJwk),
        dest: JSON.stringify(consumerJwks.publicJwk),
        encAlg: 'A256GCM',
        signingAlg: SIGNING_ALG,
        hashAlg: 'SHA-256',
        ledgerContractAddress: '8d407a1722633bdd1dcf221474be7a44c05d7c2f',
        ledgerSignerAddress: providerLedgerAddress,
        pooToPorDelay: 10000,
        pooToPopDelay: 20000,
        pooToSecretDelay: 180000 // 3 minutes
      }
      console.log(dataExchangeAgreement)

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
    })

    describe('create/verify proof of publication (PoP)', function () {
      this.timeout(120000)
      let pop: _pkg.StoredProof<_pkg.PoPPayload>
      this.beforeAll(async function () {
        pop = await nrpProvider.generatePoP()
      })
      it('provider should create a valid signed PoP that is properly verified by the consumer', async function () {
        const verified = await nrpConsumer.verifyPoP(pop.jws)
        console.log(JSON.stringify(verified.payload, undefined, 2))
        chai.expect(verified).to.not.equal(undefined)
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
}
