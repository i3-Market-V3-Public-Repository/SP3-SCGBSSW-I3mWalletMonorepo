/* eslint-disable @typescript-eslint/no-unused-expressions */

import * as _pkg from '#pkg'
import { DataExchangeAgreement, DataSharingAgreement } from '#pkg'
import { example } from './dataSharingAgreementExample'

describe('checkAgreement', function () {
  this.bail()

  const parsedPrivateKey = process.env.PRIVATE_KEY
  if (parsedPrivateKey === undefined) {
    throw new Error('You need to pass a PRIVATE_KEY as env variable. The associated address should also hold balance enough to interact with the DLT')
  }
  let dataSharingAgreement: DataSharingAgreement
  let dataExchangeAgreement: DataExchangeAgreement

  it('should validate dataSharingAgreement if it follows the required format', async function () {
    dataSharingAgreement = example.dataSharingAgreement as DataSharingAgreement
    dataExchangeAgreement = dataSharingAgreement.dataExchangeAgreement

    const errors = await _pkg.validateDataSharingAgreementSchema(dataSharingAgreement)
    if (errors.length > 0) {
      errors.forEach(error => { console.log(error.message ?? '') })
    }
    chai.expect(errors.length).to.equal(0)
  })

  it('should fail if it has more properties than expected', async function () {
    const badAgreement = { ...dataSharingAgreement, extra: 'juju' }
    const errors = await _pkg.validateDataSharingAgreementSchema(badAgreement)
    // if (errors.length > 0) console.log(errors)
    chai.expect(errors.length).to.be.greaterThan(0)
  })

  it('should fail if a did has an invalid format', async function () {
    const badParties = { ...dataSharingAgreement.parties }
    badParties.consumerDid = 'asfgag'
    const badAgreement = { ...dataSharingAgreement, parties: badParties }
    const errors = await _pkg.validateDataSharingAgreementSchema(badAgreement)
    // if (errors.length > 0) console.log(errors)
    chai.expect(errors.length).to.be.greaterThan(0)
  })

  it('should fail if it has less properties than expected', async function () {
    const badAgreement = { ...dataSharingAgreement }
    // @ts-expect-error
    delete badAgreement.purpose
    const errors = await _pkg.validateDataSharingAgreementSchema(badAgreement)
    // if (errors.length > 0) console.log(errors)
    chai.expect(errors.length).to.be.greaterThan(0)
  })

  it('should fail if a claim has a different type than the one in the schema', async function () {
    const badAgreement = { ...dataSharingAgreement }
    // @ts-expect-error
    badAgreement.purpose = 145
    const errors = await _pkg.validateDataSharingAgreementSchema(badAgreement)
    // if (errors.length > 0) console.log(errors)
    chai.expect(errors.length).to.be.greaterThan(0)
  })

  it('should validate the dataExchangeAgreement if it follows the required format', async function () {
    const errors = await _pkg.validateDataExchangeAgreement(dataExchangeAgreement)
    chai.expect(errors.length).to.equal(0)
  })
  it('should fail if it has more properties than expected', async function () {
    const badAgreement = { ...dataExchangeAgreement, extra: 'juju' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if it has less properties than expected', async function () {
    const badAgreement = { ...dataExchangeAgreement }
    // @ts-expect-error
    delete badAgreement.pooToPopDelay
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid format')).to.equal(true)
  })
  it('should fail if an address is not in hex', async function () {
    const badAgreement = { ...dataExchangeAgreement, ledgerSignerAddress: '0xjuju' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid EIP-55 address')).to.equal(true)
  })
  it('should fail if orig or dest do not hold a valid JWK', async function () {
    const badAgreement = { ...dataExchangeAgreement, orig: '{"kty":"EC","crv":"P-256","x":"Qcg51QcqVM7x2m7U_8cM7-Cndo5SVcRFXhrkSC2n_bM","y":"KLONuQwA0Tv8DeQlteWQ1Yy64iwBMCvtXOJwns1NL_8"}' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid key')).to.equal(true)
  })
  it('should fail if invalid hashAlg', async function () {
    const badAgreement = { ...dataExchangeAgreement, hashAlg: 'otro' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement as DataExchangeAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid encAlg', async function () {
    const badAgreement = { ...dataExchangeAgreement, encAlg: 'otro' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement as DataExchangeAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid algorithm')).to.equal(true)
  })
  it('should fail if invalid signingAlg', async function () {
    const badAgreement = { ...dataExchangeAgreement, signingAlg: 'otro' }
    const errors = await _pkg.validateDataExchangeAgreement(badAgreement as DataExchangeAgreement)
    chai.expect(errors.length).to.be.greaterThan(0)
    chai.expect(errors[0].nrErrors.includes('invalid algorithm')).to.equal(true)
  })
})
