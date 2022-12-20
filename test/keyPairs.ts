/* eslint-disable @typescript-eslint/no-unused-expressions */

import * as _pkg from '#pkg'
import * as b64 from '@juanelas/base64'
import { randBytes } from 'bigint-crypto-utils'

describe('verifyKeyPair for different signing algorithms', function () {
  this.timeout(60000)
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

      // console.log(JSON.stringify(pubJwk, undefined, 2))
      // console.log(JSON.stringify(privJwk, undefined, 2))
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

    describe(`${signingAlg}: encrypt with public, decrypt with private`, function () {
      let jwe: string
      const plainblocks: Uint8Array[] = []
      let cipherblocks: string[] = []
      this.beforeAll('Prepare blocks of different lengths', async function () {
        plainblocks.push(await randBytes(256))
        plainblocks.push(await randBytes(1024))
        plainblocks.push(await randBytes(1048576)) // 1MB
        plainblocks.push(await randBytes(8388608)) // 8MB
        plainblocks.push(await randBytes(67108864)) // 64MB
        plainblocks.push(await randBytes(134217728)) // 128MB
        plainblocks.push(await randBytes(268435456)) // 256MB
        plainblocks.push(await randBytes(335544320)) // 320MB
      })
      it('should encrypt with public key', async function () {
        cipherblocks = []
        for (const plainblock of plainblocks) {
          jwe = await _pkg.jweEncrypt(plainblock, pubJwk, 'A256GCM')
          cipherblocks.push(jwe)
          chai.expect(jwe).to.not.be.undefined
        }
      })
      it('decrypted cipherblock should be equal to original plaintext block', async function () {
        for (let i = 0; i < cipherblocks.length; i++) {
          const cipherblock = cipherblocks[i]
          const plainblock = plainblocks[i]
          const decryptedBlock = await _pkg.jweDecrypt(cipherblock, privJwk)
          chai.expect(b64.encode(plainblock)).to.eq(b64.encode(decryptedBlock.plaintext))
        }
      })
    })
  }
})
