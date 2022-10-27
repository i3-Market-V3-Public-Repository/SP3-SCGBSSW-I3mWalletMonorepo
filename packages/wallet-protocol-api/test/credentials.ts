import data from './data'

export default function (): void {
  it('should store verifiable credentials', async function () {
    const { api, wallet, signer, user } = data
    const credential = await wallet.veramo.agent.createVerifiableCredential({
      credential: {
        issuer: { id: signer.did },
        credentialSubject: {
          id: user.did,
          consumer: true
        }
      },
      proofFormat: 'jwt',
      save: false
    })
    await api.resources.create({
      type: 'VerifiableCredential',
      resource: credential as any
    })
  })
}
