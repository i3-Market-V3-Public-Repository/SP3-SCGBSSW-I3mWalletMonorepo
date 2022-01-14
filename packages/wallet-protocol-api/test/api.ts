import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'

const { WalletApi } = _pkg

describe('WalletApi', function () {
  let api: _pkg.WalletApi
  let did: string = ''
  let address: string = ''
  const sessionJSON = {
    masterKey: {
      from: {
        name: 'Initiator'
      },
      to: {
        name: 'Wallet desktop'
      },
      port: 29170,
      na: 'EuKsDQTXay6gzRWK-67dyw',
      nb: 'yk2mh5GUGtnfScZnRbs5UQ',
      secret: 'FS4GpUhHUmqas743RlcOkrU-EO0rAJViRV6aE092x5k'
    },
    code: '65794a68624763694f694a6b615849694c434a6c626d4d694f694a424d6a553252304e4e496e302e2e783351456c6430485a71494275554c322e7866706b35683739623638767a5150424e6e6b386d5f4745394877553745784d624a32426c47555277426f3467564f542d547a4a466877357532536f77517a39434c795536624757534738377459756d38725a646d375f4c3638614f783957693234696631536f754470444b786754536d767342644a456e5737327361714a397537504c345230652d6c6f383169552d5674316669317137596a654f4a792d4c553255465a5146346f386f516a31726774615550646e4b743358415f55627441645237507039303962466b5a6a34656e544146614b3150526a5244346b4a474856616151465831723867376a33795654506155786e63384f4e3134623667456838736a624e65724175472d7372352d726543525f76753241577665375f6b7177516465564b42374e7638446f6e3446543069755530414f547047574432734b757a4b6f7651766433663659647a366e4461694862424b69786463317a7963535a6d5f33756d6a345255305a65625f44373566563245535134676c6d5930672e793145377858596a307a7a6f75485035694457737551'
  }

  this.timeout(30000)
  before(async function () {
    const transport = new HttpInitiatorTransport()
    const session = await Session.fromJSON(transport, sessionJSON)
    api = new WalletApi(session)
  })

  it('should list identities', async function () {
    const identities = await api.identities.list()
    console.log(identities)
  })

  it('should select identities', async function () {
    const identity = await api.identities.select({
      reason: 'For a test'
    })
    console.log(identity)
    did = identity.did
  })

  it('should create identities', async function () {
    const identity = await api.identities.create({
      alias: 'Testing'
    })
    console.log(identity)
  })

  it('should get more information about identities', async function () {
    const identityInfo = await api.identities.info({ did })
    address = identityInfo.addresses[0]
    console.log(identityInfo)
  })

  it('should be able to sign using identities', async function () {
    const identity = await api.identities.sign({ did }, {
      type: 'Transaction',
      data: {
        from: address
      }
    })
    console.log(identity)
  })
})
