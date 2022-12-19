import data from './data'

export default function (): void {
  let from: string = ''

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
      const identityInfo = await data.api.identities.info({ did: 'did:ethr:i3m:0x022c6936a221d9ccc2ccebde59a1a899fd170fe01234bfb8d8efd4e62911d12b5f' })
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
}
