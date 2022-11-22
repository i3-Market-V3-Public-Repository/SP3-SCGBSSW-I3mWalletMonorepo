/* eslint-disable @typescript-eslint/no-unused-expressions */

import { WalletProtocol, HttpInitiatorTransport, Session } from '@i3m/wallet-protocol'
import { WalletApi } from '@i3m/wallet-protocol-api'
import { pinDialog, SessionManager } from '#pkg'

describe('Pairing', function () {
  this.timeout(120000)

  let sessionManager: SessionManager<HttpInitiatorTransport>
  let walletApi: WalletApi

  it('Should ask for PIN and create a secure session managed by a SessionManager', async function () {
    const transport = new HttpInitiatorTransport({ getConnectionString: pinDialog })

    const protocol = new WalletProtocol(transport)

    sessionManager = new SessionManager({ protocol })

    sessionManager
      .$session
      // We can subscribe to events when the session is deleted/end and when a new one is created
      .subscribe((session) => {
        if (session !== undefined) {
          console.log('New session loaded')
        } else {
          console.log('Session deleted')
        }
      })

    // Loads the current stored session (if any). Use it to recover a previously created session
    await sessionManager.loadSession()

    // creates a secure session (if it does not exist yet)
    await sessionManager.createIfNotExists()

    chai.expect(sessionManager.hasSession).to.be.true
  })

  it('should initialize a valid WalletAPI with the created session', async function () {
    walletApi = new WalletApi(sessionManager.session as Session<HttpInitiatorTransport>)

    const providerInfo = await walletApi.providerinfo.get()
    chai.expect(providerInfo.network).to.not.be.undefined
  })

  it('should create an identity', async () => {
    const did = (await walletApi.identities.create({ alias: 'test' })).did
    console.log('Created identity with DID' + did)

    chai.expect(did).to.not.be.undefined
  })

  it('should list wallet identities', async () => {
    const identities = await walletApi.identities.list()
    console.log(JSON.stringify(identities))

    chai.expect(identities.length > 0)
  })

  this.afterAll(async () => {
    await sessionManager.removeSession()
  })
})
