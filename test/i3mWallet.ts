import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { randBytes } from 'bigint-crypto-utils'
import { hashable } from 'object-sha'
import { I3mWalletAgentOrig, I3mWalletAgentDest } from '../src/ts/dlt/wallet-agents'

const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

describe('testing signing transactions with i3M-Wallet', function () {
  const transport = new HttpInitiatorTransport()
  const sessionObj = {
    masterKey: {
      from: {
        name: 'Initiator'
      },
      to: {
        name: 'Wallet desktop'
      },
      port: 29170,
      na: 's9MbjfciDGuekcdVszgibA',
      nb: 'sfeQUjwJUcIKsmqULLfxOg',
      secret: '1ZbCRFVZXiiHUD9a8Rc5rbDizARwil3US8GndWrLqa4'
    },
    code: '65794a68624763694f694a6b615849694c434a6c626d4d694f694a424d6a553252304e4e496e302e2e367159697557346c6b647431477571612e695032384973314f386e7533395734697a61524546644e5846314b6749785f546174416373566c5a307342374e7a524d6e6a75416836486a32535336355054336c7567596a744643556c78324a4f697a716f65754f753367777551424d31355f7574486c5773516f39516178506663383465374f3749724d3970323645566d3854396134683948635059646961794a4d6747562d7249775f67537175545755716c75726d69495a61327a796a6e41714b713847617a56517a5038395855633548686b6a78666a5945704d724d6e635a3350346e38383775785a656e724a4859327368504a6145736a5a61773649666e75666d374c6343636b52665449706e5061466b2d58774a425251724a68523257514e664f624d636862733357724d66427a7a4e6e6358437254574f6c4852514b377454465543745658586641374e64544d79646e4a4d504d4b784243664f4e7a556a465774346d485538314d6e64645173315051364470632e46346c6b556462584a4d3676463064335f4275636641'
  }
  const did = 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27'
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
