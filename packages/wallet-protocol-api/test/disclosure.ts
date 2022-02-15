import data from './data'

// const { expect } = chai

export default function (): void {
  it('should handle selective disclosures', async function () {
    const { api, wallet, validator } = data
    const sdrJwt = await wallet.veramo.agent.createSelectiveDisclosureRequest({
      data: {
        issuer: validator.did,
        claims: [
          { claimType: 'consumer', essential: true },
          { claimType: 'age' }
        ]
      }
    })
    const response = await api.disclosure.disclose({ jwt: sdrJwt })
    console.log(response)
  })
}
