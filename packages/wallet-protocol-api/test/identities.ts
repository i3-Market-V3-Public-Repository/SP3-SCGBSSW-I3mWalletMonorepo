import data from './data'

export default function (): void {
  let from: string = ''
  let jwt: string = ''

  it('should create identities', async function () {
    const { api } = data
    const identity = await api.identities.create({
      alias: 'Testing'
    })
    chai.expect(identity).to.have.key('did')
  })

  it('should list identities', async function () {
    const { api } = data
    const identities = await api.identities.list()
    chai.expect(identities.length).to.be.greaterThan(0)
  })

  it('should select identities', async function () {
    const { api } = data
    const identity = await api.identities.select({
      reason: 'Select one identity for the test'
    })
    chai.expect(identity).to.have.key('did')
    data.user = identity
  })

  it('should get more information about identities', async function () {
    const { api } = data
    const identityInfo = await api.identities.info(data.user)
    chai.expect(identityInfo).to.have.keys('did', 'alias', 'provider', 'addresses')
    if (identityInfo.addresses !== undefined) {
      from = identityInfo.addresses[0]
    }
  })

  it('should fail when trying to get more information about a non-existing identity', async function () {
    try {
      await data.api.identities.info({ did: 'did:ethr:i3m:0x022c6936a221d9ccc2ccebde59a1a899fd170fe01234bfb8d8efd4e62911d12b5f' })
      chai.expect(false)
    } catch (error) {
      console.log((error as Error).message)
      chai.expect(true)
    }
  })

  it('should be able to sign transactions using identities', async function () {
    const { api } = data
    const response = await api.identities.sign(data.user, {
      type: 'Transaction',
      data: { from }
    })
    chai.expect(response).to.have.key('signature')
  })

  it('should generate a signed JWT', async function () {
    const header = { headerField1: 'hello' }
    const payload = { payloadField1: 'yellow', payloadField2: 'brown' }
    jwt = (await data.api.identities.sign(data.user, { type: 'JWT', data: { header, payload } })).signature
    chai.expect(jwt).to.not.be.undefined
    console.log('generated JWT: ' + jwt)
  })

  it('a JWT with a DID (that is resolved in the connected DLT) as issuer can be verified by the wallet', async function () {
    const verification = await data.api.didJwt.verify({ jwt })
    console.log('verification: ' + JSON.stringify(verification, undefined, 2))
    chai.expect(verification.verification).to.equal('success')
  })

  it('verification of the JWT will also succeed if a expected claim is found in the payload', async function () {
    const verification = await data.api.didJwt.verify({
      jwt,
      expectedPayloadClaims: {
        payloadField1: 'yellow'
      }
    })
    console.log('verification: ' + JSON.stringify(verification, undefined, 2))
    chai.expect(verification.verification).to.equal('success')
  })

  it('verification of the JWT will fail if a expected claim is not in the payload', async function () {
    const verification = await data.api.didJwt.verify({
      jwt,
      expectedPayloadClaims: {
        noneExistingField: ''
      }
    })
    console.log('verification: ' + JSON.stringify(verification, undefined, 2))
    chai.expect(verification.verification).to.equal('failed')
  })

  it('verification of the JWT will fail if the signature is invalid', async function () {
    const verification = await data.api.didJwt.verify({
      jwt: jwt.slice(0, -10) + 'aAbBcCdDeE'
    })
    console.log('verification: ' + JSON.stringify(verification, undefined, 2))
    chai.expect(verification.verification).to.equal('failed')
  })
}
