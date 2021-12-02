import { exportJWK, generateKeyPair } from 'jose'

describe('unit tests on non-repudiation protocol', function () {
  let npProvider: _pkgTypes.NonRepudiationOrig
  let npConsumer: _pkgTypes.NonRepudiationDest

  this.beforeAll(async () => {
    const block = new Uint8Array([0, 2, 0, 1, 0])
    const dataExchangeId = '231412432'

    const consumerKeys = await generateKeyPair(_pkg.SIGNING_ALG, { extractable: true })
    const consumerJwks: _pkgTypes.JwkPair = {
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
    const providerJwks: _pkgTypes.JwkPair = {
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

  describe('create/verify proof of Origin', function () {
    it('should create a valid signed proof of origin that is properly verified', async function () {
      const poo = await npProvider.generatePoO()
      const verification = await npConsumer.verifyPoO(poo, npProvider.block.jwe as string)
      chai.expect(verification).to.not.equal(undefined)
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
  //     const poO: _pkgTypes.PoO = {
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
})
