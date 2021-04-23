import generateKeyPair from 'jose/util/generate_key_pair'
import { KeyLike } from 'jose/webcrypto/types'
import CompactSign from 'jose/jws/compact/sign'
import CompactEncrypt from 'jose/jwe/compact/encrypt'
import parseJwk from 'jose/jwk/parse'
import createHash from 'create-hash'
import chaiAsPromised from 'chai-as-promised'

chai.use(chaiAsPromised)
const expect = chai.expect

describe('unit tests on non repudiable protocol functions', function () {
  // let publicKeyConsumer: KeyLike
  // let privateKeyConsumer: KeyLike

  let publicKeyProvider: KeyLike
  let privateKeyProvider: KeyLike

  let publicKeyBackplane: KeyLike
  let privateKeyBackplane: KeyLike

  this.beforeAll(async () => {
    // const consumerkey = await generateKeyPair('EdDSA')
    // publicKeyConsumer = consumerkey.publicKey
    // privateKeyConsumer = consumerkey.privateKey

    const providerkey = await generateKeyPair('EdDSA')
    publicKeyProvider = providerkey.publicKey
    privateKeyProvider = providerkey.privateKey

    const backplainkey = await generateKeyPair('EdDSA')
    publicKeyBackplane = backplainkey.publicKey
    privateKeyBackplane = backplainkey.privateKey
  })

  describe('- testing on validateProof functions used by a non repudiable protocol ', function () {
    describe('test proof or Origin validation function', function () {
      it('should validate a proof of Origin', async function () {
        const cipherblock: string = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..iGBwDtGeYus_82ma.NHuFqetSBzQ0.gISeRgIszus0FPZ_TuNyvA'
        const hashCipherBlock: string = createHash('sha256').update(cipherblock).digest('hex')

        const poO: _pkgTypes.poO = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            id: 3,
            orig: 'urn:example:issuer',
            dest: 'urn:example:subject',
            block_id: 4,
            block_desc: 'description',
            hash_alg: 'sha256',
            cipherblock_dgst: hashCipherBlock,
            block_commitment: 'd8a73ab676c0b1bd31ad3831da5d8bea768d58935ffd7369aeca2dea8a61580a',
            key_commitment: 'b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jws = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        const valPoo = await _pkg.validatePoO(publicKeyProvider, jws, cipherblock)
        expect(valPoo).to.be.true // eslint-disable-line
      })

      it('should not validate a proof of Origin with wrong key', async function () {
        const cipherblock: string = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..iGBwDtGeYus_82ma.NHuFqetSBzQ0.gISeRgIszus0FPZ_TuNyvA'
        const hashCipherBlock: string = createHash('sha256').update(cipherblock).digest('hex')

        const poO: _pkgTypes.poO = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            id: 3,
            orig: 'urn:example:issuer',
            dest: 'urn:example:subject',
            block_id: 4,
            block_desc: 'description',
            hash_alg: 'sha256',
            cipherblock_dgst: hashCipherBlock,
            block_commitment: 'd8a73ab676c0b1bd31ad3831da5d8bea768d58935ffd7369aeca2dea8a61580a',
            key_commitment: 'b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jws = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        await expect(_pkg.validatePoO(publicKeyBackplane, jws, cipherblock)).to.be.rejected
      })

      it('should not validate a proof of Origin with wrong iat', async function () {
        const cipherblock: string = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..iGBwDtGeYus_82ma.NHuFqetSBzQ0.gISeRgIszus0FPZ_TuNyvA'
        const hashCipherBlock: string = createHash('sha256').update(cipherblock).digest('hex')
        const poO: _pkgTypes.poO = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: 1614607746,
          exchange: {
            id: 3,
            orig: 'urn:example:issuer',
            dest: 'urn:example:subject',
            block_id: 4,
            block_desc: 'description',
            hash_alg: 'sha256',
            cipherblock_dgst: hashCipherBlock,
            block_commitment: 'd8a73ab676c0b1bd31ad3831da5d8bea768d58935ffd7369aeca2dea8a61580a',
            key_commitment: 'b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'
          }
        }

        expect(hashCipherBlock).is.equal(poO.exchange.cipherblock_dgst)

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jws = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        await expect(_pkg.validatePoO(publicKeyProvider, jws, cipherblock)).to.be.rejectedWith('timestamp error')
      })

      it('should not validate a proof of Origin, when the hashed CipherBlock received is different from the one saved in the poO cipherblock_dgst parameter', async function () {
        const cipherblock: string = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..iGBwDtGeYus_82ma.NHuFqetSBzQ0.gISeRgIszus0FPZ_TuNyvA'

        const poO: _pkgTypes.poO = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: 1614607746,
          exchange: {
            id: 3,
            orig: 'urn:example:issuer',
            dest: 'urn:example:subject',
            block_id: 4,
            block_desc: 'description',
            hash_alg: 'sha256',
            cipherblock_dgst: 'DIFFERENT-CIPHERBLOCK',
            block_commitment: 'd8a73ab676c0b1bd31ad3831da5d8bea768d58935ffd7369aeca2dea8a61580a',
            key_commitment: 'b28c94b2195c8ed259f0b415aaee3f39b0b2920a4537611499fa044956917a21'
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jws = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        // const hashCipherBlock: string = crypto.createHash('sha256').update(cipherblock).digest('hex')

        await expect(_pkg.validatePoO(publicKeyProvider, jws, cipherblock)).to.be.rejectedWith('the cipherblock_dgst parameter in the proof of origin does not correspond to hash of the cipherblock received by the provider')
      })
    })

    describe('test proof or Receipt validation function', function () {
      it('should validate a proof of Receipt', async function () {
        const providerPoO: string = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJzdWIiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiaWF0IjoxNjEzNzQ5MTAzMTU0LCJleGNoYW5nZSI6eyJpZCI6Mywib3JpZyI6InVybjpleGFtcGxlOmlzc3VlciIsImRlc3QiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiYmxvY2tfaWQiOjQsImJsb2NrX2Rlc2MiOiJkZXNjcmlwdGlvbiIsImhhc2hfYWxnIjoic2hhMjU2IiwiY2lwaGVyYmxvY2tfZGdzdCI6IjljNTMxNjhjOWRiN2U3OTRkMGZiNTcyM2JiZGE1NjEzMGM3MGZjZWY4ZTFmMjFhMTRkMGEwMzNmYzRlNmYzYjciLCJibG9ja19jb21taXRtZW50IjoiZDhhNzNhYjY3NmMwYjFiZDMxYWQzODMxZGE1ZDhiZWE3NjhkNTg5MzVmZmQ3MzY5YWVjYTJkZWE4YTYxNTgwYSIsImtleV9jb21taXRtZW50IjoiYjI4Yzk0YjIxOTVjOGVkMjU5ZjBiNDE1YWFlZTNmMzliMGIyOTIwYTQ1Mzc2MTE0OTlmYTA0NDk1NjkxN2EyMSJ9fQ.NRpGSnnK3O_gwuTbD6A-dnOXy2M3fS6n0WYlPX2Eo2OWG_Y_Gqf86lp6ENepwEa_vaFhwkkNwovTyjv2uSFvDw'
        const poR: _pkgTypes.poR = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            poo_dgst: 'c08abbcb1e3370a0aed9ca722b321c664282811dc7c027664b08911b93e7c04e',
            hash_alg: 'sha256',
            exchangeId: 3
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poR))
        const jwsPor = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        const valPoR = await _pkg.validatePoR(publicKeyProvider, jwsPor, providerPoO)
        expect(valPoR).to.be.true // eslint-disable-line
      })

      it('should not validate a proof of Receipt with wrong iat', async function () {
        const providerPoO: string = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJzdWIiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiaWF0IjoxNjEzNzQ5MTAzMTU0LCJleGNoYW5nZSI6eyJpZCI6Mywib3JpZyI6InVybjpleGFtcGxlOmlzc3VlciIsImRlc3QiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiYmxvY2tfaWQiOjQsImJsb2NrX2Rlc2MiOiJkZXNjcmlwdGlvbiIsImhhc2hfYWxnIjoic2hhMjU2IiwiY2lwaGVyYmxvY2tfZGdzdCI6IjljNTMxNjhjOWRiN2U3OTRkMGZiNTcyM2JiZGE1NjEzMGM3MGZjZWY4ZTFmMjFhMTRkMGEwMzNmYzRlNmYzYjciLCJibG9ja19jb21taXRtZW50IjoiZDhhNzNhYjY3NmMwYjFiZDMxYWQzODMxZGE1ZDhiZWE3NjhkNTg5MzVmZmQ3MzY5YWVjYTJkZWE4YTYxNTgwYSIsImtleV9jb21taXRtZW50IjoiYjI4Yzk0YjIxOTVjOGVkMjU5ZjBiNDE1YWFlZTNmMzliMGIyOTIwYTQ1Mzc2MTE0OTlmYTA0NDk1NjkxN2EyMSJ9fQ.NRpGSnnK3O_gwuTbD6A-dnOXy2M3fS6n0WYlPX2Eo2OWG_Y_Gqf86lp6ENepwEa_vaFhwkkNwovTyjv2uSFvDw'
        const poR: _pkgTypes.poR = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now() - 560000,
          exchange: {
            poo_dgst: 'c08abbcb1e3370a0aed9ca722b321c664282811dc7c027664b08911b93e7c04e',
            hash_alg: 'sha256',
            exchangeId: 3
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poR))
        const jwsPor = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        await expect(_pkg.validatePoR(publicKeyProvider, jwsPor, providerPoO)).to.be.rejectedWith('timestamp error')
      })

      it('should not validate a proof of Receipt with wrong key', async function () {
        const providerPoO: string = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJzdWIiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiaWF0IjoxNjEzNzQ5MTAzMTU0LCJleGNoYW5nZSI6eyJpZCI6Mywib3JpZyI6InVybjpleGFtcGxlOmlzc3VlciIsImRlc3QiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiYmxvY2tfaWQiOjQsImJsb2NrX2Rlc2MiOiJkZXNjcmlwdGlvbiIsImhhc2hfYWxnIjoic2hhMjU2IiwiY2lwaGVyYmxvY2tfZGdzdCI6IjljNTMxNjhjOWRiN2U3OTRkMGZiNTcyM2JiZGE1NjEzMGM3MGZjZWY4ZTFmMjFhMTRkMGEwMzNmYzRlNmYzYjciLCJibG9ja19jb21taXRtZW50IjoiZDhhNzNhYjY3NmMwYjFiZDMxYWQzODMxZGE1ZDhiZWE3NjhkNTg5MzVmZmQ3MzY5YWVjYTJkZWE4YTYxNTgwYSIsImtleV9jb21taXRtZW50IjoiYjI4Yzk0YjIxOTVjOGVkMjU5ZjBiNDE1YWFlZTNmMzliMGIyOTIwYTQ1Mzc2MTE0OTlmYTA0NDk1NjkxN2EyMSJ9fQ.NRpGSnnK3O_gwuTbD6A-dnOXy2M3fS6n0WYlPX2Eo2OWG_Y_Gqf86lp6ENepwEa_vaFhwkkNwovTyjv2uSFvDw'
        const poR: _pkgTypes.poR = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            poo_dgst: 'c08abbcb1e3370a0aed9ca722b321c664282811dc7c027664b08911b93e7c04e',
            hash_alg: 'sha256',
            exchangeId: 3
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poR))
        const jwsPor = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        await expect(_pkg.validatePoR(publicKeyBackplane, jwsPor, providerPoO)).to.be.rejected
      })

      it('should not validate a consumer poR that contains an hashed poO different from the one created by the provider', async function () {
        const providerPoO: string = 'DeyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1ZXIiLCJzdWIiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiaWF0IjoxNjEzNzQ5MTAzMTU0LCJleGNoYW5nZSI6eyJpZCI6Mywib3JpZyI6InVybjpleGFtcGxlOmlzc3VlciIsImRlc3QiOiJ1cm46ZXhhbXBsZTpzdWJqZWN0IiwiYmxvY2tfaWQiOjQsImJsb2NrX2Rlc2MiOiJkZXNjcmlwdGlvbiIsImhhc2hfYWxnIjoic2hhMjU2IiwiY2lwaGVyYmxvY2tfZGdzdCI6IjljNTMxNjhjOWRiN2U3OTRkMGZiNTcyM2JiZGE1NjEzMGM3MGZjZWY4ZTFmMjFhMTRkMGEwMzNmYzRlNmYzYjciLCJibG9ja19jb21taXRtZW50IjoiZDhhNzNhYjY3NmMwYjFiZDMxYWQzODMxZGE1ZDhiZWE3NjhkNTg5MzVmZmQ3MzY5YWVjYTJkZWE4YTYxNTgwYSIsImtleV9jb21taXRtZW50IjoiYjI4Yzk0YjIxOTVjOGVkMjU5ZjBiNDE1YWFlZTNmMzliMGIyOTIwYTQ1Mzc2MTE0OTlmYTA0NDk1NjkxN2EyMSJ9fQ.NRpGSnnK3O_gwuTbD6A-dnOXy2M3fS6n0WYlPX2Eo2OWG_Y_Gqf86lp6ENepwEa_vaFhwkkNwovTyjv2uSFvDw'
        const poR: _pkgTypes.poR = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            poo_dgst: 'c08abbcb1e3370a0aed9ca722b321c664282811dc7c027664b08911b93e7c04e',
            hash_alg: 'sha256',
            exchangeId: 3
          }
        }

        const jwt: Uint8Array = new TextEncoder().encode(JSON.stringify(poR))
        const jwsPor = await new CompactSign(jwt)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        await expect(_pkg.validatePoR(publicKeyProvider, jwsPor, providerPoO)).to.be.rejectedWith('the hashed proof of origin received does not correspond to the poo_dgst parameter in the proof of origin')
      })
    })

    describe('test validateCipherblock function', function () {
      it('should validate a cipherblock with key', async function () {
        const text = 'test'
        const jwk = {
          kty: 'oct',
          alg: 'HS256',
          k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
          kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
        }
        const key = await parseJwk(jwk)

        /* TO-DO: Fix. It cannot be any ! */
        const poO: any = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            block_commitment: createHash('sha256').update(text).digest('hex')
          }
        }

        const cipherblock = await new CompactEncrypt(new TextEncoder().encode(text))
          .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
          .encrypt(key)

        const decodedCiphertext = await _pkg.validateCipherblock(publicKeyProvider, cipherblock, jwk, poO)
        expect(decodedCiphertext).to.be.true // eslint-disable-line
      })

      it('the consumer should not validate the cipherblock, when a diffrent one is present in the proof of Origin', async function () {
        const text = 'test'
        const wrongText = 'wrongtest'

        const jwk = {
          kty: 'oct',
          alg: 'HS256',
          k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
          kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
        }
        const key = await parseJwk(jwk)

        const poO: any = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            block_commitment: createHash('sha256').update(wrongText).digest('hex')
          }
        }

        const cipherblock = await new CompactEncrypt(new TextEncoder().encode(text))
          .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
          .encrypt(key)

        await expect(_pkg.validateCipherblock(publicKeyProvider, cipherblock, jwk, poO)).to.be.rejectedWith('hashed CipherBlock not correspond to block_commitment parameter included in the proof of origin')
      })
    })

    describe('test poP validation function', function () {
      it('should validate a poP', async function () {
        const jwk = {
          kty: 'oct',
          alg: 'HS256',
          k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
          kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
        }

        const poO: any = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            key_commitment: createHash('sha256').update(JSON.stringify(jwk)).digest('hex')
          }
        }
        const jwtPoO: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jwsPoO = await new CompactSign(jwtPoO)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        const poP: any = {
          test: 'testPop'
        }
        const jwtPoP: Uint8Array = new TextEncoder().encode(JSON.stringify(poP))
        const jwsPop = await new CompactSign(jwtPoP)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyBackplane)

        const validatePoP = await _pkg.validatePoP(publicKeyBackplane, publicKeyProvider, jwsPop, jwk, jwsPoO)
        expect(validatePoP).to.be.true // eslint-disable-line
      })

      it('should not validate a poP with wrong key', async function () {
        const jwk = {
          kty: 'oct',
          alg: 'HS256',
          k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
          kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
        }

        const poO: any = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            key_commitment: createHash('sha256').update(JSON.stringify(jwk)).digest('hex')
          }
        }
        const jwtPoO: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jwsPoO = await new CompactSign(jwtPoO)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        const poP: any = {
          test: 'testPop'
        }
        const jwtPoP: Uint8Array = new TextEncoder().encode(JSON.stringify(poP))
        const jwsPop = await new CompactSign(jwtPoP)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyBackplane)

        await expect(_pkg.validatePoP(publicKeyProvider, publicKeyProvider, jwsPop, jwk, jwsPoO)).to.be.rejected
      })

      it('should not validate the poP verification function, if the hash of the key received is different from the one stored in the PoO ', async function () {
        const jwk = {
          kty: 'oct',
          alg: 'HS256',
          k: 'dVOgj6K8cpTctejWonQ58oVwSlIwFU5PaRWnYO_ep_8',
          kid: 'RUTNQtuuAJRN10314exvBpkO9v-Pp2-Bjbr21mbE0Og'
        }

        const poO: any = {
          iss: 'urn:example:issuer',
          sub: 'urn:example:subject',
          iat: Date.now(),
          exchange: {
            key_commitment: createHash('sha256').update('DIFFERENT-JWK', 'utf8').digest('hex')
          }
        }
        const jwtPoO: Uint8Array = new TextEncoder().encode(JSON.stringify(poO))
        const jwsPoO = await new CompactSign(jwtPoO)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyProvider)

        const poP: any = {
          test: 'testPop'
        }
        const jwtPoP: Uint8Array = new TextEncoder().encode(JSON.stringify(poP))
        const jwsPop = await new CompactSign(jwtPoP)
          .setProtectedHeader({ alg: 'EdDSA' })
          .sign(privateKeyBackplane)

        await expect(_pkg.validatePoP(publicKeyBackplane, publicKeyProvider, jwsPop, jwk, jwsPoO)).to.be.rejectedWith('hashed key not correspond to poO key_commitment parameter')
      })
    })
  })
})
