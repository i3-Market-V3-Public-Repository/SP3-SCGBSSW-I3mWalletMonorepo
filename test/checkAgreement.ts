describe('checkAgreement', function () {
  const agreement: _pkg.DataExchangeAgreement = {
    orig: '{"kty":"EC","crv":"P-256","x":"Qcg51QcqVM7x2m7U_8cM7-Cndo5SVcRFXhrkSC2n_bM","y":"KLONuQwA0Tv8DeQlteWQ1Yy64iwBMCvtXOJwns1NL_8","alg":"ES256"}',
    dest: '{"kty":"EC","crv":"P-256","x":"VXsBuOZwVjhofJV4kAhba6wn1EYDwUIkgXb2fVnL8xc","y":"h4fL5Qv4EYt7XdKqdIy1ZJs4_QWYDkY1zUzSoI61N7Y","alg":"ES256"}',
    encAlg: 'A256GCM',
    signingAlg: 'ES256',
    hashAlg: 'SHA-256',
    ledgerContractAddress: '8d407a1722633bdd1dcf221474be7a44c05d7c2f',
    ledgerSignerAddress: '17bd12c2134afc1f6e9302a532efe30c19b9e903',
    pooToPorDelay: 10000,
    pooToPopDelay: 20000,
    pooToSecretDelay: 180000
  }
  it('should return a parsed agreement strictly following the required format', async function () {
    const parsedAgreement = await _pkg.checkAgreement(agreement)
    console.log(JSON.stringify(parsedAgreement, undefined, 2))
    chai.expect(parsedAgreement).to.not.equal(undefined)
  })
  it('should fail if it has more properties than expected', async function () {
    const badAgreement = { ...agreement, extra: 'juju' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement)
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
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if an address is not in hex', async function () {
    const badAgreement = { ...agreement, ledgerSignerAddress: '0xjuju' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if orig or dest do not hold a valid JWK', async function () {
    const badAgreement = { ...agreement, orig: '{"kty":"EC","crv":"P-256","x":"Qcg51QcqVM7x2m7U_8cM7-Cndo5SVcRFXhrkSC2n_bM","y":"KLONuQwA0Tv8DeQlteWQ1Yy64iwBMCvtXOJwns1NL_8"}' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid key')).to.equal(true)
  })
  it('should fail if invalid hashAlg', async function () {
    const badAgreement = { ...agreement, hashAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid encAlg', async function () {
    const badAgreement = { ...agreement, encAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid signingAlg', async function () {
    const badAgreement = { ...agreement, signingAlg: 'otro' }
    let err: _pkg.NrError = new _pkg.NrError(new Error('error'), ['unexpected error'])
    try {
      await _pkg.checkAgreement(badAgreement as _pkg.DataExchangeAgreement)
    } catch (error) {
      err = error as _pkg.NrError
    }
    chai.expect(err.nrErrors.includes('invalid algorithm')).to.equal(true)
  })
})
