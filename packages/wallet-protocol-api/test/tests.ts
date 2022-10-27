import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import data from './data'
import createWallet from './wallet'
import sessionJSON from './session-token'
import identities from './identities'
import credentials from './credentials'
import disclosure from './disclosure'

import { WalletApi } from '#pkg'

// async function importTest (name: string, path: string): Promise<void> {
//   const test = await import(path)
//   describe(name, test.default)
// }

describe('WalletApi', function () {
  this.timeout(30000)
  this.beforeAll(async function () {
    // Create api
    const session = await Session.fromJSON(HttpInitiatorTransport, sessionJSON)
    data.api = new WalletApi(session)

    // Create wallet
    data.wallet = await createWallet()
    data.validator = await data.wallet.identityCreate({ alias: 'Validator' })
    data.signer = await data.wallet.identityCreate({ alias: 'Signer' })
  })

  describe('#identities', identities)
  describe('#credentials', credentials)
  describe('#disclosure', disclosure)
  // importTest('#disclosure', './disclosure')
})
