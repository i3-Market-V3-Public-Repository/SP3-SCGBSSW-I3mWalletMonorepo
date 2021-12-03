import { exportJWK, generateKeyPair } from 'jose'
import { hashable } from 'object-sha'

describe('Non-repudiation protocol', function () {
  this.timeout(20000)

  let npProvider: _pkg.NonRepudiationOrig
  let npConsumer: _pkg.NonRepudiationDest
  const dltConfig: _pkg.DltConfig = {
    rpcProviderUrl: '***REMOVED***',
    disable: true
  }

  this.beforeAll(async () => {
    const block = new Uint8Array([0, 2, 0, 1, 0])
    const dataExchangeId = '231412432'

    const consumerKeys = await generateKeyPair(_pkg.SIGNING_ALG, { extractable: true })
    const consumerJwks: _pkg.JwkPair = {
      privateJwk: {
        ...await exportJWK(consumerKeys.privateKey),
        alg: _pkg.SIGNING_ALG
      },
      publicJwk: {
        ...await exportJWK(consumerKeys.publicKey),
        alg: _pkg.SIGNING_ALG
      }
    }

    const providerKeys = await generateKeyPair(_pkg.SIGNING_ALG, { extractable: true })
    const providerJwks: _pkg.JwkPair = {
      privateJwk: {
        ...await exportJWK(providerKeys.privateKey),
        alg: _pkg.SIGNING_ALG
      },
      publicJwk: {
        ...await exportJWK(providerKeys.publicKey),
        alg: _pkg.SIGNING_ALG
      }
    }

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
      const verification = await npConsumer.verifyPoO(poo, npProvider.block.jwe as string)
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
    it('provider should create a valid signed PoP that is properly verified by the consumer', async function () {
      const pop = await npProvider.generatePoP()
      let verified
      try {
        verified = await npConsumer.verifyPoP(pop, npProvider.block.secret as _pkg.JWK)
      } catch (error) {
      }
      chai.expect(verified).to.not.equal(undefined)
    })
    it('verification should throw error if there is no PoR', async function () {
      const block = npConsumer.block as _pkg.OrigBlock
      const por = block.por
      delete block.por
      let err
      try {
        await npConsumer.verifyPoP(block.pop as string, block.secret as _pkg.JWK)
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
  })

  describe('decrypt and verify decrypted cipherblock', function () {
    it('consumer should be able to decrypt and hash(decrypted block) should be equal to the dataExchange.blockCommitment', async function () {
      const decryptedBlock = await npConsumer.decrypt()
      chai.expect(hashable(npProvider.block.raw)).to.equal((decryptedBlock !== undefined) ? hashable(decryptedBlock) : '')
    })
    it('should throw error if PoP has not been previously verified', async function () {
      const block = npConsumer.block as _pkg.DestBlock
      const pop = block.pop as string
      block.pop = undefined

      let err
      try {
        await npConsumer.decrypt()
      } catch (error) {
        err = error
      }

      block.pop = pop

      chai.expect(err).to.not.be.undefined // eslint-disable-line
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

      chai.expect(err).to.not.be.undefined // eslint-disable-line
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
      chai.expect(err).to.not.be.undefined // eslint-disable-line
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
      chai.expect(err).to.not.be.undefined // eslint-disable-line
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
      chai.expect(err).to.not.be.undefined // eslint-disable-line
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
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
  })

  describe('testing with a jwk with no \'alg\'', function () {
    it('verifyProof should throw error', async function () {
      let err
      try {
        const jwk = { ...npProvider.publicJwkDest }
        delete jwk.alg
        await _pkg.verifyProof(npConsumer.block?.poo as string, jwk, npProvider.exchange as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
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
      chai.expect(err).to.be.an.instanceOf(TypeError)
    })
  })

  describe('Actions when not initialized', function () {
    it('npOrig should fail and throw error', async function () {
      const npProv = new _pkg.NonRepudiationOrig('asfddsaf', npProvider.jwkPairOrig, npProvider.publicJwkDest, npProvider.block.raw, dltConfig)
      let err
      try {
        await npProv.generatePoO()
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
    it('npDest should fail and throw error', async function () {
      const npCons = new _pkg.NonRepudiationDest('asfddsaf', npConsumer.jwkPairDest, npConsumer.publicJwkOrig, dltConfig)
      let err
      try {
        await npCons.generatePoR()
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
  })
})
