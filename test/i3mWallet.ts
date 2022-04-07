import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { randBytes } from 'bigint-crypto-utils'
import { hashable } from 'object-sha'
import { I3mWalletAgentOrig, I3mWalletAgentDest } from '../src/ts/dlt/wallet-agents'
import walletSetup from './i3mWalletSetup.json'

const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

describe('testing signing transactions with i3M-Wallet', function () {
  const transport = new HttpInitiatorTransport()
  const sessionObj = walletSetup.token
  const did = walletSetup.did
  let session: Session<HttpInitiatorTransport>
  let nrpProvider: _pkg.NonRepudiationProtocol.NonRepudiationOrig
  let nrpConsumer: _pkg.NonRepudiationProtocol.NonRepudiationDest

  this.beforeAll(async function () {
    session = await Session.fromJSON(transport, sessionObj)
    const providerWallet = new I3mWalletAgentOrig(session, did)
    const consumerWallet = new I3mWalletAgentDest()

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
      ledgerSignerAddress: await providerWallet.getAddress(),
      pooToPorDelay: 10000,
      pooToPopDelay: 20000,
      pooToSecretDelay: 180000 // 3 minutes
    }
    console.log(dataExchangeAgreement)

    nrpProvider = new _pkg.NonRepudiationProtocol.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, providerWallet)
    nrpConsumer = new _pkg.NonRepudiationProtocol.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, consumerWallet)
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
