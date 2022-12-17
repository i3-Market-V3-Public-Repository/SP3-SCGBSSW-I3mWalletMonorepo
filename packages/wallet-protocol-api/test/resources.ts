/* eslint-disable @typescript-eslint/no-unused-expressions */

import { Contract, KeyPair } from '@i3m/base-wallet'
import { parseJwk, JWK } from '@i3m/non-repudiation-library'
import data from './data'

export default function (): void {
  let keyPairId: string

  it('should store a key pair', async function () {
    const deaExample = await import('./dataSharingAgreementExample')
    const keyPair: KeyPair = {
      keyPair: {
        privateJwk: await parseJwk(deaExample.example.providerJwks.privateJwk as JWK, true),
        publicJwk: await parseJwk(deaExample.example.providerJwks.publicJwk as JWK, true)
      }
    }
    const response = await data.api.resources.create({ resource: keyPair, type: 'KeyPair' })
    if (response.id !== undefined) keyPairId = response.id
    chai.expect(keyPairId).to.not.be.undefined
  })

  it('should store a data sharing agreement template', async function () {
    const deaExample = await import('./dataSharingAgreementExample')
    const contract: Contract = {
      dataSharingAgreement: deaExample.example.dataSharingAgreement as Contract['dataSharingAgreement'],
      keyPair: {
        privateJwk: await parseJwk(deaExample.example.providerJwks.privateJwk as JWK, true),
        publicJwk: await parseJwk(deaExample.example.providerJwks.publicJwk as JWK, true)
      }
    }
    const response = await data.api.resources.create({ resource: contract, type: 'Contract' })
    if (response.id !== undefined) keyPairId = response.id
    chai.expect(keyPairId).to.not.be.undefined
  })

  it('should list all resources', async function () {
    const resources = await data.api.resources.list()
    chai.expect(resources.length).to.be.greaterThan(0)
  })

  it('should list only verifiable credentials', async function () {
    const resources = await data.api.resources.list({ type: 'VerifiableCredential' })
    chai.expect(resources.length).to.be.greaterThan(0)
    resources.forEach(resource => {
      chai.expect(resource.type).to.equal('VerifiableCredential')
    })
  })

  it('should list only contracts', async function () {
    const resources = await data.api.resources.list({ type: 'Contract' })
    chai.expect(resources.length).to.be.greaterThan(0)
    resources.forEach(resource => {
      chai.expect(resource.type).to.equal('Contract')
    })
  })
}
