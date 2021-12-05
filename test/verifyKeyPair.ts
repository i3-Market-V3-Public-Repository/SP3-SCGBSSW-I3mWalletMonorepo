import { exportJWK, generateKeyPair } from 'jose'

/* eslint-disable @typescript-eslint/no-unused-expressions */

describe('verifyKeyPair for different signing algorithms', function () {
  this.timeout(20000)
  const signingAlgsToTest: _pkg.SigningAlg[] = ['ES256', 'ES512', 'PS256']

  for (const signingAlg of signingAlgsToTest) {
    let privJwk: _pkg.JWK
    let pubJwk: _pkg.JWK
    let privJwk2: _pkg.JWK

    this.beforeAll(async () => {
      const keyPair = await generateKeyPair(signingAlg, { extractable: true })
      privJwk = {
        ...await exportJWK(keyPair.privateKey),
        alg: signingAlg
      }
      pubJwk = {
        ...await exportJWK(keyPair.publicKey),
        alg: signingAlg
      }

      const keyPair2 = await generateKeyPair(signingAlg, { extractable: true })
      privJwk2 = {
        ...await exportJWK(keyPair2.privateKey),
        alg: signingAlg
      }
    })

    describe(`${signingAlg}: verifyKeyPair(pubJwk, privJwk)`, function () {
      it('should succeed', async function () {
        let err
        try {
          await _pkg.verifyKeyPair(pubJwk, privJwk)
        } catch (error) {
          err = error
        }
        chai.expect(err).to.be.undefined
      })
      it('should throw an error with non-complementary keys', async function () {
        try {
          await _pkg.verifyKeyPair(pubJwk, privJwk2)
        } catch (error) {
          chai.expect(error)
        }
      })
    })
  }
})
