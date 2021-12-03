import { exportJWK, generateKeyPair } from 'jose'
import { hashable } from 'object-sha'

describe('unit tests on non-repudiation protocol', function () {
  this.timeout(20000)

  let npProvider: _pkg.NonRepudiationOrig
  let npConsumer: _pkg.NonRepudiationDest

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

    npProvider = new _pkg.NonRepudiationOrig(dataExchangeId, providerJwks, consumerJwks.publicJwk, block)
    npConsumer = new _pkg.NonRepudiationDest(dataExchangeId, consumerJwks, providerJwks.publicJwk)

    await npProvider.init()
    await npConsumer.init()
  })

  describe('create proof of publication (PoP)', function () {
    it('should fail since there are not previous PoR', async function () {
      const verificationCode = 'code'
      let err
      try {
        await npProvider.generatePoP(verificationCode)
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
      const verificationCode = 'code'
      const pop = await npProvider.generatePoP(verificationCode)
      const { verified, decryptedBlock } = await npConsumer.verifyPoPAndDecrypt(pop, JSON.stringify(npProvider.block.secret), verificationCode)
      chai.expect(verified).to.not.equal(undefined)
      chai.expect(hashable(npProvider.block.raw)).to.equal(hashable(decryptedBlock))
    })
  })

  describe('testing with invalid claims', function () {
    it('using \'issr\' instead of \'iss\' should throw error', async function () {
      const expectedPayload = {
        issr: 'orig',
        dataExchange: npConsumer.dataExchange
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
        dataExchange: npConsumer.dataExchange
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
        dataExchange: {
          ...npConsumer.dataExchange,
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
        await _pkg.verifyProof(npConsumer.block?.poo as string, npConsumer.jwkPairDest.publicJwk, npConsumer.dataExchange as unknown as _pkg.ProofInputPayload)
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
        await _pkg.verifyProof(npConsumer.block?.poo as string, jwk, npProvider.dataExchange as unknown as _pkg.ProofInputPayload)
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
          dataExchange: npProvider.dataExchange
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
      const npProv = new _pkg.NonRepudiationOrig('asfddsaf', npProvider.jwkPairOrig, npProvider.publicJwkDest, npProvider.block.raw, _pkg.SIGNING_ALG)
      let err
      try {
        await npProv.generatePoO()
      } catch (error) {
        err = error
      }
      chai.expect(err).to.not.be.undefined // eslint-disable-line
    })
    it('npDest should fail and throw error', async function () {
      const npCons = new _pkg.NonRepudiationDest('asfddsaf', npConsumer.jwkPairDest, npConsumer.publicJwkOrig)
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

// describe('testing on createProof functions', function () {
// describe('create proof or Receipt', function () {
//   it('should create a proof of Receipt signed with the consumer private key that can be validated using the consumer public key', async function () {
//     const poOProof: string = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJzdWIiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiaWF0IjoxNjEzNzQ5MTAzMTU0LCJleGNoYW5nZSI6eyJpZCI6Mywib3JpZyI6InVybjpleGFtcGxlOmlzc3VlciIsImRlc3QiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiYmxvY2tfaWQiOjQsImJsb2NrX2Rlc2MiOiJkZXNjcmlwdGlvbiIsImhhc2hfYWxnIjoic2hhMjU2IiwiY2lwaGVyYmxvY2tfZGdzdCI6IjljNTMxNjhjOWRiN2U3OTRkMGZiNTcyM2JiZGE1NjEzMGM3MGZjZWY4ZTFmMjFhMTRkMGEwMzNmYzRlNmYzYjciLCJibG9ja19jb21taXRtZW50IjoiZDhhNzNhYjY3NmMwYjFiZDMxYWQzODMxZGE1ZDhiZWE3NjhkNTg5MzVmZmQ3MzY5YWVjYTJkZWE4YTYxNTgwYSIsImtleV9jb21taXRtZW50IjoiYjI4Yzk0YjIxOTVjOGVkMjU5ZjBiNDE1YWFlZTNmMzliMGIyOTIwYTQ1Mzc2MTE0OTlmYTA0NDk1NjkxN2EyMSJ9fQ.NRpGSnnK3O_gwuTbD6A-dnOXy2M3fS6n0WYlPX2Eo2OWG_Y_Gqf86lp6ENepwEa_vaFhwkkNwovTyjv2uSFvDw'
//     const responsePoR = await _pkg.createPoR(privateKeyConsumer, poOProof, 'urn:example:issuer', 'urn:example:subject', 3)
//     const { payload } = await compactVerify(responsePoR, publicKeyConsumer)

//     const hashPoO: string = await _pkg.sha(poOProof)
//     const decodedPayload = JSON.parse(new TextDecoder().decode(payload).toString())
//     chai.expect(hashPoO).to.equal(decodedPayload.exchange.poo_dgst)
//     chai.expect(decodedPayload.iss).to.equal('urn:example:issuer')
//     chai.expect(decodedPayload.sub).to.equal('urn:example:subject')
//   })
// })

// describe('sign a proof', function () {
//   it('should create a valid jws of the jwt proof', async function () {
//     const proof = { test: 'example' }
//     const signedProof = await _pkg.signProof(privateKeyConsumer, proof)
//     const { payload } = await compactVerify(signedProof, publicKeyConsumer)
//     chai.expect(JSON.stringify(proof)).to.equal((new TextDecoder().decode(payload)))
//   })
// })

// describe('create account object for backplain API', function () {
//   it('should create a valid json object', async function () {
//     const poO: _pkg.PoO = {
//       iss: 'urn:example:issuer',
//       sub: 'urn:example:subject',
//       iat: Date.now(),
//       exchange: {
//         id: 3,
//         orig: 'urn:example:issuer',
//         dest: 'urn:example:subject',
//         block_id: 4,
//         block_desc: 'description',
//         hash_alg: 'sha256',
//         cipherblock_dgst: 'fc766e56ad7f0d9ccd9b98af742468a0f58bbaba3e45e6b452c4357845bc450d',
//         block_commitment: 'd8a73ab676c0b1bd31ad3831da5d8bea768d58935ffd7369aeca2dea8a61580a',
//         key_commitment: 'b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'
//       }
//     }
//     const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
//     const jwsPoO = await new CompactSign(jwt)
//       .setProtectedHeader({ alg: _pkg.SIGNING_ALG })
//       .sign(privateKeyProvider)

//     const poRProof: string = 'null'
//     const jwk: JWK = {
//       kty: 'oct',
//       alg: 'HS256',
//       k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
//       kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
//     }
//     const sendblockchainJson: any = await _pkg.createBlockchainProof(publicKeyProvider, jwsPoO, poRProof, jwk)

//     chai.expect(sendblockchainJson.privateStorage).to.have.property('availability', 'privateStorage')
//     chai.expect(sendblockchainJson.blockchain).to.have.property('availability', 'blockchain')
//     chai.expect(sendblockchainJson.blockchain.content).to.have.deep.include({ 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og': jwk })
//   })
// })
// })
