import { hashable } from 'object-sha'
import { randBytes } from 'bigint-crypto-utils'
import { DataExchange } from '../src/ts'
import { importJWK, jwtVerify } from 'jose'

describe('Non-repudiation protocol', function () {
  this.timeout(20000)
  const SIGNING_ALG: _pkg.SigningAlg = 'ES256'

  let npProvider: _pkg.NonRepudiationOrig
  let npConsumer: _pkg.NonRepudiationDest
  const dltConfig: Partial<_pkg.DltConfig> = {
    rpcProviderUrl: '***REMOVED***',
    disable: false
  }
  let dataExchangeAgreement: _pkg.DataExchangeAgreement

  this.beforeAll(async () => {
    const block = new Uint8Array(await randBytes(256))

    const consumerJwks: _pkg.JwkPair = await _pkg.generateKeys(SIGNING_ALG)
    console.log(JSON.stringify({ consumerKeys: consumerJwks }, undefined, 2))

    const providerPrivKeyHex = '***REMOVED***'
    const providerJwks: _pkg.JwkPair = await _pkg.generateKeys(SIGNING_ALG, providerPrivKeyHex)
    console.log(JSON.stringify({ providerKeys: providerJwks }, undefined, 2))

    dataExchangeAgreement = {
      orig: JSON.stringify(providerJwks.publicJwk),
      dest: JSON.stringify(consumerJwks.publicJwk),
      encAlg: 'A256GCM',
      signingAlg: SIGNING_ALG,
      hashAlg: 'SHA-256',
      ledgerContractAddress: '8d407a1722633bdd1dcf221474be7a44c05d7c2f',
      ledgerSignerAddress: '17bd12c2134afc1f6e9302a532efe30c19b9e903',
      pooToPorDelay: 10000,
      pooToPopDelay: 20000,
      pooToSecretDelay: 180000 // 3 minutes
    }

    console.log(dataExchangeAgreement)

    npProvider = new _pkg.NonRepudiationOrig(dataExchangeAgreement, providerJwks.privateJwk, block, dltConfig)
    npConsumer = new _pkg.NonRepudiationDest(dataExchangeAgreement, consumerJwks.privateJwk, dltConfig)
  })

  describe('create/verify proof of origin (PoO)', function () {
    let poo: _pkg.StoredProof
    this.beforeAll(async function () {
      poo = await npProvider.generatePoO()
    })
    it('provider should create a valid signed PoO that is properly verified by the consumer', async function () {
      const verification = await npConsumer.verifyPoO(poo.jws, npProvider.block.jwe)
      chai.expect(verification).to.not.equal(undefined)
    })
    it('verification should throw error if the PoO is not within date tolerance', async function () {
      const currentDate = new Date(Date.now() - 60 * 3600 * 1000) // 1 hour before

      let err
      try {
        await npConsumer.verifyPoO(poo.jws, npProvider.block.jwe, undefined, currentDate)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('create/verify proof of reception (PoR)', function () {
    let por: _pkg.StoredProof
    this.beforeAll(async function () {
      por = await npConsumer.generatePoR()
    })
    it('consumer should create a valid signed PoR that is properly verified by the provider', async function () {
      const verification = await npProvider.verifyPoR(por.jws)
      chai.expect(verification).to.not.equal(undefined)
    })
    it('verification should throw error if there is no previously generated PoO', async function () {
      const block = npProvider.block
      const poo = block.poo
      delete block.poo
      let err
      try {
        await npProvider.verifyPoR(por.jws)
      } catch (error) {
        err = error
      }
      block.poo = poo
      chai.expect(err).to.not.equal(undefined)
    })
    it('verification should throw error if the PoR is not within date tolerance', async function () {
      const currentDate = new Date(Date.now() + 1 * 3600 * 1000) // 1 hour after
      const clockToleranceMs = 1000

      let err
      try {
        await npProvider.verifyPoR(por.jws, clockToleranceMs, currentDate)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('create/verify proof of publication (PoP)', function () {
    this.timeout(120000)
    let pop: _pkg.StoredProof
    this.beforeAll(async function () {
      pop = await npProvider.generatePoP()
    })
    it('provider should create a valid signed PoP that is properly verified by the consumer', async function () {
      const verified = await npConsumer.verifyPoP(pop.jws)
      console.log(JSON.stringify(verified.payload, undefined, 2))
      chai.expect(verified).to.not.equal(undefined)
    })
    it('verification should throw error if there is no PoR', async function () {
      const block = npConsumer.block
      const por = block.por
      delete block.por
      let err
      try {
        await npConsumer.verifyPoP(pop.jws)
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.equal(undefined)
    })
    it('verification should throw error if the PoP is not within date tolerance', async function () {
      const currentDate = new Date(Date.now() + 60 * 3600 * 1000) // 1 hour after
      const clockToleranceMs = 1

      let err
      try {
        await npConsumer.verifyPoP(pop.jws, clockToleranceMs, currentDate)
      } catch (error) {
        err = error
      }
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
      const append = '123'
      const exchange = npConsumer.exchange as _pkg.DataExchange
      exchange.blockCommitment = npConsumer.exchange?.blockCommitment as string + append
      let err
      try {
        await npConsumer.decrypt()
      } catch (error) {
        err = error
      }
      // restore the block commitment
      exchange.blockCommitment = exchange.blockCommitment.substring(0, exchange.blockCommitment.length - append.length)

      chai.expect(err).to.not.equal(undefined)
    })
  })

  if (dltConfig.disable !== true) {
    describe('get secret from ledger', function () {
      const timeout = 150000 // 2.5 minutes (we currently have one block every 2 minutes)
      this.timeout(timeout)
      it('should be the same secret as the one obtained in the PoP', async function () {
        const secret = { ...npConsumer.block.secret }
        const secretFromLedger = await npConsumer.getSecretFromLedger()
        chai.expect(hashable(secret)).to.equal(hashable(secretFromLedger))
        npConsumer.block.secret = secret as _pkg.Block['secret']
      })
    })
  }

  describe('verification request', function () {
    it('a consumer should be able to generate a valid JWS', async function () {
      const verificationRequest = await npConsumer.generateVerificationRequest()
      const verified = await jwtVerify(verificationRequest, await importJWK(npConsumer.jwkPairDest.publicJwk))
      chai.expect(verified.payload).to.not.equal(undefined)
    })
    it('a provider should be able to generate a valid JWS', async function () {
      const verificationRequest = await npProvider.generateVerificationRequest()
      const verified = await jwtVerify(verificationRequest, await importJWK(npProvider.jwkPairOrig.publicJwk))
      chai.expect(verified.payload).to.not.equal(undefined)
    })
    it('should fail if there is no previous PoR (consumer side)', async function () {
      const block = npConsumer.block
      const por = block.por
      delete block.por
      let err
      try {
        await npConsumer.generateVerificationRequest()
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.equal(undefined)
    })
    it('should fail if there is no previous PoR (provider side)', async function () {
      const block = npProvider.block
      const por = block.por
      delete block.por
      let err
      try {
        await npProvider.generateVerificationRequest()
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('dispute request', function () {
    it('a consumer should be able to generate it', async function () {
      const disputeRequest = await npConsumer.generateDisputeRequest()
      const verified = await jwtVerify(disputeRequest, await importJWK(npConsumer.jwkPairDest.publicJwk))
      chai.expect(verified.payload).to.not.equal(undefined)
    })
    it('should fail if there is no previous PoR', async function () {
      const block = npConsumer.block
      const por = block.por
      delete block.por
      let err
      try {
        await npConsumer.generateDisputeRequest()
      } catch (error) {
        err = error
      }
      block.por = por
      chai.expect(err).to.not.equal(undefined)
    })
    it('should fail if there is no previously receive cipherblock', async function () {
      const block = npConsumer.block
      const jwe = block.jwe
      delete block.jwe
      let err
      try {
        await npConsumer.generateDisputeRequest()
      } catch (error) {
        err = error
      }
      block.jwe = jwe
      chai.expect(err).to.not.equal(undefined)
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
        await _pkg.verifyProof(npConsumer.block?.poo?.jws as string, npConsumer.publicJwkOrig, expectedPayload as unknown as _pkg.ProofInputPayload)
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
        await _pkg.verifyProof(npConsumer.block?.poo?.jws as string, npConsumer.publicJwkOrig, expectedPayload as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
    it('property in expectedDataExchange different that in the dataExchange should throw error', async function () {
      const expectedPayload: _pkg.ProofInputPayload = {
        iss: 'orig',
        proofType: 'por',
        exchange: {
          ...npConsumer.exchange as DataExchange,
          dest: 'asdfdgdg'
        }
      }
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo?.jws as string, npConsumer.publicJwkOrig, expectedPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('testing with invalid key', function () {
    it('should throw error', async function () {
      const expectedPayload: _pkg.ProofInputPayload = {
        iss: 'orig',
        proofType: 'por',
        exchange: {
          ...npConsumer.exchange as DataExchange,
          dest: 'asdfdgdg'
        }
      }
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo?.jws as string, npConsumer.jwkPairDest.publicJwk, expectedPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
  })

  describe('testing with a jwk with no \'alg\'', function () {
    it('verifyProof should throw error', async function () {
      const jwk = { ...npProvider.publicJwkDest }
      // @ts-expect-error
      delete jwk.alg
      let err
      try {
        await _pkg.verifyProof(npConsumer.block?.poo?.jws as string, jwk, npProvider.exchange as unknown as _pkg.ProofInputPayload)
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.equal(undefined)
    })
    it('createProof should throw error', async function () {
      let err
      try {
        const jwk = { ...npProvider.jwkPairOrig.privateJwk }
        // @ts-expect-error
        delete jwk.alg
        const payload: _pkg.PoOInputPayload = {
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
