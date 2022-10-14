import { randBytes } from 'bigint-crypto-utils'
import * as _pkg from '#pkg'

describe('oneTimeSecret (encAlg: EncryptionAlg, secret?: Uint8Array|string, base64?: boolean)', function () {
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
  it('should throw error if provided secret does not meet the required algorithm secret length', async function () {
    const secret = await randBytes(13)
    let err
    try {
      await _pkg.oneTimeSecret('A128GCM', secret)
    } catch (error) {
      err = error
    }
    chai.expect(err).to.not.equal(undefined)
  })
})
