describe('verifyKeyPair for different signing algorithms', function () {
  this.timeout(20000)
  const signingAlgsToTest: _pkg.SigningAlg[] = ['ES256', 'ES384', 'ES512']

  for (const signingAlg of signingAlgsToTest) {
    let privJwk: _pkg.JWK
    let pubJwk: _pkg.JWK
    let privJwk2: _pkg.JWK

    this.beforeAll(async () => {
      ({ publicJwk: pubJwk, privateJwk: privJwk } = await _pkg.generateKeys(signingAlg));
      // console.log({ pub1: pubJwk })
      // console.log({ priv1: privJwk });

      ({ privateJwk: privJwk2 } = await _pkg.generateKeys(signingAlg))
      // console.log({ priv2: privJwk2 })
    })

    describe(`${signingAlg}: verifyKeyPair(pubJwk, privJwk)`, function () {
      it('should succeed', async function () {
        let err
        try {
          await _pkg.verifyKeyPair(pubJwk, privJwk)
        } catch (error) {
          err = error
        }
        chai.expect(err).to.equal(undefined)
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
