import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import sessionJSON from './session-token'

const { WalletApi } = _pkg
const { expect } = chai

describe('WalletApi', function () {
  let api: _pkg.WalletApi
  let did: string = ''
  let from: string = ''

  this.timeout(30000)
  before(async function () {
    const session = await Session.fromJSON(HttpInitiatorTransport, sessionJSON)
    api = new WalletApi(session)
  })

  it('should list identities', async function () {
    const identities = await api.identities.list()
    expect(identities.length).to.be.greaterThan(0)
  })

  it('should select identities', async function () {
    const identity = await api.identities.select({
      reason: 'For a test'
    })
    expect(identity).to.have.key('did')
    did = identity.did
  })

  it('should create identities', async function () {
    const identity = await api.identities.create({
      alias: 'Testing'
    })
    expect(identity).to.have.key('did')
  })

  it('should get more information about identities', async function () {
    const identityInfo = await api.identities.info({ did })
    expect(identityInfo).to.have.keys('did', 'alias', 'provider', 'addresses')
    from = identityInfo.addresses[0]
  })

  it('should be able to sign transactions using identities', async function () {
    const response = await api.identities.sign({ did }, {
      type: 'Transaction',
      data: {
        from
      }
    })
    expect(response).to.have.key('signature')
    console.log(response.signature)
  })
})
