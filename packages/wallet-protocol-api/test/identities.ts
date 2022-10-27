import data from './data'

export default function (): void {
  let from: string = ''

  it('should list identities', async function () {
    const { api } = data
    const identities = await api.identities.list()
    chai.expect(identities.length).to.be.greaterThan(0)
  })

  it('should select identities', async function () {
    const { api } = data
    const identity = await api.identities.select({
      reason: 'For a test'
    })
    chai.expect(identity).to.have.key('did')
    data.user = identity
  })

  it('should create identities', async function () {
    const { api } = data
    const identity = await api.identities.create({
      alias: 'Testing'
    })
    chai.expect(identity).to.have.key('did')
  })

  it('should get more information about identities', async function () {
    const { api } = data
    const identityInfo = await api.identities.info(data.user)
    chai.expect(identityInfo).to.have.keys('did', 'alias', 'provider', 'addresses')
    if (identityInfo.addresses !== undefined) {
      from = identityInfo.addresses[0]
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
