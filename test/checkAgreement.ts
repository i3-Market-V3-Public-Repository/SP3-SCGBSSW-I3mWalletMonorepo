/* eslint-disable @typescript-eslint/no-unused-expressions */

import * as _pkg from '#pkg'
import { ethers } from 'ethers'

describe('checkAgreement', function () {
  const parsedPrivateKey = process.env.PRIVATE_KEY
  if (parsedPrivateKey === undefined) {
    throw new Error('You need to pass a PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
  }
  const privateKey = _pkg.parseHex(parsedPrivateKey, true)
  const address = ethers.utils.computeAddress(privateKey)

  const agreement: _pkg.DataExchangeAgreement = {
    orig: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"Qcg51QcqVM7x2m7U_8cM7-Cndo5SVcRFXhrkSC2n_bM","y":"KLONuQwA0Tv8DeQlteWQ1Yy64iwBMCvtXOJwns1NL_8"}',
    dest: '{"alg":"ES256","crv":"P-256","kty":"EC","x":"VXsBuOZwVjhofJV4kAhba6wn1EYDwUIkgXb2fVnL8xc","y":"h4fL5Qv4EYt7XdKqdIy1ZJs4_QWYDkY1zUzSoI61N7Y"}',
    encAlg: 'A256GCM',
    signingAlg: 'ES256',
    hashAlg: 'SHA-256',
    ledgerContractAddress: '0x8d407A1722633bDD1dcf221474be7a44C05d7c2F',
    ledgerSignerAddress: address,
    pooToPorDelay: 10000,
    pooToPopDelay: 20000,
    pooToSecretDelay: 180000
  }
  it('should validate the agreement if it follows the required format', async function () {
    let validated = false
    try {
      await _pkg.validateAgreement(agreement)
      validated = true
      console.log(JSON.stringify(agreement, undefined, 2))
      chai.expect(agreement).to.not.equal(undefined)
    } catch (error) {}
    chai.expect(validated).to.be.true
  })
  it('should fail if it has more properties than expected', async function () {
    const badAgreement = { ...agreement, extra: 'juju' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if it has less properties than expected', async function () {
    const badAgreement = { ...agreement }
    // @ts-expect-error
    delete badAgreement.pooToPopDelay
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if an address is not in hex', async function () {
    const badAgreement = { ...agreement, ledgerSignerAddress: '0xjuju' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if orig or dest do not hold a valid JWK', async function () {
    const badAgreement = { ...agreement, orig: '{"kty":"EC","crv":"P-256","x":"Qcg51QcqVM7x2m7U_8cM7-Cndo5SVcRFXhrkSC2n_bM","y":"KLONuQwA0Tv8DeQlteWQ1Yy64iwBMCvtXOJwns1NL_8"}' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid key')).to.equal(true)
  })
  it('should fail if invalid hashAlg', async function () {
    const badAgreement = { ...agreement, hashAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid encAlg', async function () {
    const badAgreement = { ...agreement, encAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid signingAlg', async function () {
    const badAgreement = { ...agreement, signingAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.validateAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
})
