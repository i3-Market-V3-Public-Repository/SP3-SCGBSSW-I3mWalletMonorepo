import { hashable } from 'object-sha'
import { randBytes } from 'bigint-crypto-utils'
import * as b64 from '@juanelas/base64'

describe('Non-repudiation protocol', function () {
  this.timeout(20000)
  const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

  let npProvider: _pkg.NonRepudiationOrig
  let npConsumer: _pkg.NonRepudiationDest
  const dltConfig: Partial<_pkg.DltConfig> = {
    rpcProviderUrl: '***REMOVED***'
  }

  this.beforeAll(async () => {
    const block = new Uint8Array(await randBytes(256))
    const dataExchangeId: string = b64.encode(await randBytes(32), true, false) // is a bse64 representation of a uint256

    const consumerJwks: _pkg.JwkPair = await _pkg.generateKeys(SIGNING_ALG)
    console.log(JSON.stringify({ consumerKeys: consumerJwks }, undefined, 2))

    const providerPrivKeyHex = '***REMOVED***'
    const providerJwks: _pkg.JwkPair = await _pkg.generateKeys(SIGNING_ALG, providerPrivKeyHex)
    console.log({ providerKeys: providerJwks })

    npProvider = new _pkg.NonRepudiationOrig(dataExchangeId, providerJwks, consumerJwks.publicJwk, block, dltConfig)
    npConsumer = new _pkg.NonRepudiationDest(dataExchangeId, consumerJwks, providerJwks.publicJwk, dltConfig)

    await npProvider.init()
    await npConsumer.init()
  })

  describe('create proof of publication (PoP)', function () {
    it('should fail since there are not previous PoR', async function () {
      let err
      try {
        await npProvider.generatePoP()
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
  })

  describe('create proof of reception (PoR)', function () {
    it('should fail since there are not previous PoO', async function () {
      let err
      try {
        await npConsumer.generatePoR()
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
  })

  describe('create/verify proof of origin (PoO)', function () {
    it('provider should create a valid signed PoO that is properly verified by the consumer', async function () {
      const poo = await npProvider.generatePoO()
      const verification = await npConsumer.verifyPoO(poo, npProvider.block.jwe)
      chai.expect(verification).to.not.equal(undefined)
    })
  })

  describe('create/verify proof of reception (PoR)', function () {
    it('consumer should create a valid signed PoR that is properly verified by the provider', async function () {
      const por = await npConsumer.generatePoR()
      const verification = await npProvider.verifyPoR(por)
      chai.expect(verification).to.not.equal(undefined)
    })
  })

  describe('create/verify proof of publication (PoP)', function () {
    this.timeout(120000)
    it('provider should create a valid signed PoP that is properly verified by the consumer', async function () {
      const pop = await npProvider.generatePoP()
      const verified = await npConsumer.verifyPoP(pop)
      console.log(JSON.stringify(verified.payload, undefined, 2))
      chai.expect(verified).to.not.equal(undefined)
    })
    it('verification should throw error if there is no PoR', async function () {
      const block = npConsumer.block as _pkg.OrigBlock
      const por = block.por
      delete block.por
      let err
      try {
        await npConsumer.verifyPoP(block.pop as string)
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('decrypt and verify decrypted cipherblock', function () {
    it('consumer should be able to decrypt and hash(decrypted block) should be equal to the dataExchange.blockCommitment', async function () {
      const decryptedBlock = await npConsumer.decrypt()
      chai.expect(hashable(npProvider.block.raw)).to.equal((decryptedBlock !== undefined) ? hashable(decryptedBlock) : '')
    })
    it('should throw error if there is no secret yet', async function () {
      const secret = npConsumer.block.secret
      delete npConsumer.block.secret

      let err
      try {
        await npConsumer.decrypt()
      } catch (error) {
        err = error
      }
      npConsumer.block.secret = secret
      chai.expect(err).to.not.equal(undefined)
    })
    it('it should throw error if hash(decrypted block) != committed block digest', async function () {
      const str = '123'
      npConsumer.exchange.blockCommitment = npConsumer.exchange.blockCommitment as string + str
      let err
      try {
        await npConsumer.decrypt()
      } catch (error) {
        err = error
      }
      // restore the block commitment
      npConsumer.exchange.blockCommitment = npConsumer.exchange.blockCommitment.substring(0, npConsumer.exchange.blockCommitment.length - str.length)

      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('get secret from ledger', function () {
    const timeout = 150000 // 2.5 minutes (we currently have one block every 2 minutes)
    this.timeout(timeout)
    it('should be the same secret as the one obtained in the PoP', async function () {
      const secret = { ...npConsumer.block.secret }
      const secretFromLedger = await npConsumer.getSecretFromLedger(timeout / 1000 - 2)
      chai.expect(hashable(secret)).to.equal(hashable(secretFromLedger))
      npConsumer.block.secret = secret as _pkg.Block['secret']
    })
  })

  describe('testing with invalid claims', function () {
    it('using \'issr\' instead of \'iss\' should throw error', async function () {
      const expectedPayload = {
        issr: 'orig',
        exchange: npConsumer.exchange
      }
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo as string, npConsumer.publicJwkOrig, expectedPayload as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
    it('adding unknown property \'x\' to expectedDataExchange claims should throw error', async function () {
      const expectedPayload = {
        iss: 'orig',
        x: 'afasf',
        exchange: npConsumer.exchange
      }
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo as string, npConsumer.publicJwkOrig, expectedPayload as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
    it('property in expectedDataExchange different that in the dataExchange should throw error', async function () {
      const expectedPayload = {
        iss: 'orig',
        exchange: {
          ...npConsumer.exchange,
          dest: 'asdfdgdg'
        }
      }
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo as string, npConsumer.publicJwkOrig, expectedPayload as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('testing with invalid key', function () {
    it('should throw error', async function () {
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo as string, npConsumer.jwkPairDest.publicJwk, npConsumer.exchange as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('testing with a jwk with no \'alg\'', function () {
    it('verifyProof should throw error', async function () {
      const jwk = { ...npProvider.publicJwkDest }
      delete jwk.alg
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo as string, jwk, npProvider.exchange as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
    it('createProof should throw error', async function () {
      let err
      try {
        const jwk = { ...npProvider.jwkPairOrig.privateJwk }
        delete jwk.alg
        const payload: _pkg.PoOPayload = {
          proofType: 'PoO',
          iss: 'orig',
          exchange: npProvider.exchange
        }
        await _pkg.createProof(payload, jwk)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })
})
