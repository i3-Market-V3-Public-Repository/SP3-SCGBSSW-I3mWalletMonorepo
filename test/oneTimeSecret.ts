import * as _pkg from '#pkg'
import { randBytes } from 'bigint-crypto-utils'

describe('oneTimeSecret (encAlg: EncryptionAlg, secret?: Uint8Array|string, base64?: boolean)', function () {
  this.timeout(30000)

  it('should work with AES-128-GCM', async function () {
    const otp = await _pkg.oneTimeSecret('A128GCM')
    chai.expect(otp).to.not.equal(undefined)
  })
  it('should work with AES-256-GCM', async function () {
    const otp = await _pkg.oneTimeSecret('A256GCM')
    chai.expect(otp).to.not.equal(undefined)
  })
  it('should work with provided secret as a hex string', async function () {
    const otp = await _pkg.oneTimeSecret('A128GCM', '61323432316539663837653832333136')
    chai.expect(otp).to.not.equal(undefined)
  })
  it('should work with provided secret as a base64 string', async function () {
    const otp = await _pkg.oneTimeSecret('A128GCM', 'YTI0MjFlOWY4N2U4MjMxNg', true)
    chai.expect(otp).to.not.equal(undefined)
  })
  it('should work with provided secret as a Uint8Array', async function () {
    const secret = await randBytes(16)
    const otp = await _pkg.oneTimeSecret('A128GCM', secret)
    chai.expect(otp).to.not.equal(undefined)
  })
  it('should throw error if provided secret does not meet the required algorithm secret length (Uint8Array | Buffer)', async function () {
    const secret = await randBytes(13)
    let err
    try {
      await _pkg.oneTimeSecret('A128GCM', secret)
    } catch (error) {
      err = error
    }
    chai.expect(err).to.not.equal(undefined)
  })
  it('should throw error if provided secret does not meet the required algorithm secret length (hex string)', async function () {
    let err
    try {
      await _pkg.oneTimeSecret('A128GCM', '6132343231653966383765383233313')
    } catch (error) {
      err = error
    }
    chai.expect(err).to.not.equal(undefined)
  })
  it('should be able to encrypt and decrypt different block lengths using a one-time secret', async function () {
    const secret = await _pkg.oneTimeSecret('A128GCM')
    console.log(JSON.stringify(secret.jwk, undefined, 2))

    const plaintexts: Uint8Array[] = []

    plaintexts.push(await randBytes(256))
    plaintexts.push(await randBytes(1024))
    // plaintexts.push(await randBytes(1048576)) // 1MB
    // plaintexts.push(await randBytes(8388608)) // 8MB
    // plaintexts.push(await randBytes(67108864)) // 64MB
    // plaintexts.push(await randBytes(134217728)) // 128MB
    // plaintexts.push(await randBytes(268435456)) // 256MB
    plaintexts.push(await randBytes(335544320)) // 320MB
    // plaintexts.push(await randBytes(402653184)) // 384MB

    for (const plaintext of plaintexts) {
      const jwe = await _pkg.jweEncrypt(plaintext, secret.jwk)
      const decrypted = await _pkg.jweDecrypt(jwe, secret.jwk)
      chai.expect(decrypted.plaintext).to.eql(plaintext)
    }
  })
})
