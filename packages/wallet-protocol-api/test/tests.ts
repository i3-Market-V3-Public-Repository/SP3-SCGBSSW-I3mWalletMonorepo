import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import data from './data'
import createWallet from './wallet'
import sessionJSON from './session-token'

const { WalletApi } = _pkg

function importTest (name: string, path: string): void {
  const test = require(path) // eslint-disable-line
  describe(name, test.default)
}

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

  importTest('#identities', './identities')
  importTest('#credentials', './credentials')
  importTest('#disclosure', './disclosure')
})
