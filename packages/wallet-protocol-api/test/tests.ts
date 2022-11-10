import { HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import data from './data'
import createWallet from './wallet'
import identities from './identities'
import credentials from './credentials'
import disclosure from './disclosure'
import resources from './resources'

import { WalletApi } from '#pkg'

// async function importTest (name: string, path: string): Promise<void> {
//   const test = await import(path)
//   describe(name, test.default)
// }

const sessionObjJson = process.env.I3M_WALLET_SESSION_TOKEN as string

if (IS_BROWSER) {
  console.log('This test is not executed in a browser (server wallet only works on node). Skipping')
} else if (sessionObjJson === undefined) {
  console.log(`Skipping test.
You need to pass a I3M_WALLET_SESSION_TOKEN as env variable.
Steps for creating a token:
 - Set your wallet in pairing mode. A PIN appears in the screen
 - Connect a browser to http://localhost:29170/pairing
   - If session is ON (PIN is not requested), click "Remove session" and then "Start protocol"
   - Fill in the PIN
   - After succesful pairing, click "Session to clipboard"
 - Edit your .env file or add a new environment variable in you CI provider with key I3M_WALLET_SESSION_TOKEN and value the pasted contents`)
} else {
  describe('WalletApi', function () {
    this.timeout(30000)
    this.beforeAll(async function () {
      // Create api
      const sessionObj = JSON.parse(sessionObjJson)

      const session = await Session.fromJSON(HttpInitiatorTransport, sessionObj)
      data.api = new WalletApi(session)

      // Create wallet
      data.wallet = await createWallet()
      data.validator = await data.wallet.identityCreate({ alias: 'Validator' })
      data.signer = await data.wallet.identityCreate({ alias: 'Signer' })
    })

    describe('#identities', identities)
    describe('#credentials', credentials)
    describe('#disclosure', disclosure)
    describe('#resources', resources)
  })
}
