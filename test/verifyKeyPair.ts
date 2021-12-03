import { exportJWK, generateKeyPair } from 'jose'

describe('verifyKeyPair', function () {
  this.timeout(20000)

  let privJwk: _pkg.JWK
  let pubJwk: _pkg.JWK
  let privJwk2: _pkg.JWK
  let pubJwk2: _pkg.JWK

  this.beforeAll(async () => {
    const keyPair = await generateKeyPair(_pkg.SIGNING_ALG, { extractable: true })
    privJwk = {
      ...await exportJWK(keyPair.privateKey),
      alg: _pkg.SIGNING_ALG
    }
    pubJwk = {
      ...await exportJWK(keyPair.publicKey),
      alg: _pkg.SIGNING_ALG
    }

    const keyPair2 = await generateKeyPair(_pkg.SIGNING_ALG, { extractable: true })
    privJwk2 = {
      ...await exportJWK(keyPair2.privateKey),
      alg: _pkg.SIGNING_ALG
    }
    pubJwk2 = {
      ...await exportJWK(keyPair2.publicKey),
      alg: _pkg.SIGNING_ALG
    }
  })

  describe('verify with non complementary public-private keys', function () {
    it('verifyKeyPair(pubJwk, privJwk2) should throw an error', async function () {
      try {
        await _pkg.verifyKeyPair(pubJwk, privJwk2)
      } catch (error) {
        chai.expect(error)
      }
    })
    it('verifyKeyPair(pubJwk2, privJwk) should throw an error', async function () {
      try {
        await _pkg.verifyKeyPair(pubJwk2, privJwk)
      } catch (error) {
        chai.expect(error)
      }
    })
  })
})
