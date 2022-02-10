import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import sessionJSON from './session-token'

const { WalletApi } = _pkg
// const { expect } = chai

describe('WalletApi.disclosure', function () {
  let api: _pkg.WalletApi

  this.timeout(30000)
  before(async function () {
    const session = await Session.fromJSON(HttpInitiatorTransport, sessionJSON)
    api = new WalletApi(session)
  })

  it('should list identities', async function () {
    const identities = await api.disclosure.disclose({ jwt: 'blabla' })
    console.log(identities)
  })
})
