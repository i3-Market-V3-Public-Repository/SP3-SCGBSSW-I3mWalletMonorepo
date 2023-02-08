/* eslint-disable @typescript-eslint/no-unused-expressions */
import { VaultClient } from '#pkg'
import { setTimeout } from 'timers/promises'

import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import { importJwk, jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { config as loadEnvFile } from 'dotenv'
import axios, { AxiosError } from 'axios'
import { randomBytes } from 'crypto'
import { expect } from 'chai'

loadEnvFile()

const serverUrl = process.env.WCV_SERVER_URL ?? 'http://localhost:3000'
const username = process.env.WCV_USERNAME ?? 'testUser'
const password = process.env.WCV_PASSWORD ?? 'mysupersuperpassword'

const user = {
  did: 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
  username,
  password
}

const apiVersion: string = 'v' + (process.env.npm_package_version?.split('.')[0] ?? '2')

describe('Wallet Cloud-Vault', function () {
  this.timeout(30000) // ms
  let client1: VaultClient
  let client2: VaultClient
  let publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey

  before('should connect two clients to the Cloud Vault Server and get the server\'s public key', async function () {
    client1 = new VaultClient(serverUrl, user.username, user.password, '1')
    client2 = new VaultClient(serverUrl, user.username, user.password, '2')

    client1.on(client1.defaultEvents.error, error => {
      console.log(client1.name, ': ', error)
    })
    client2.on(client1.defaultEvents.error, error => {
      console.log(client1.name, ': ', error)
    })

    const resPublicJwk = await client1.getServerPublicKey()
    chai.expect(publicJwk).to.not.be.null
    if (resPublicJwk !== null) publicJwk = resPublicJwk
    try {
      await importJwk(publicJwk as JWK)
      chai.expect(true)
    } catch (error) {
      this.skip()
    }
  })

  after('Close clients', function (done) {
    client1.close()
    client2.close()
    done()
  })

  it('it should register the test user', async function () {
    try {
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify({
          did: user.did,
          username: client1.username,
          authkey: await client1.getAuthKey()
        })),
        publicJwk as JWK,
        'A256GCM'
      )
      const res = await axios.get<OpenApiPaths.ApiV2Registration$Data.Get.Responses.$201>(
        serverUrl + `/api/${apiVersion}/registration/` + data
      )
      chai.expect(res.status).to.equal(201)
    } catch (error) {
      if (error instanceof AxiosError) {
        console.log('error', error.response?.data)
      } else {
        console.log('error', error)
      }
      chai.expect(false)
    }
  })

  it('should be able to connect to server using registered credentials', async function () {
    const client1Connected = await client1.login()
    const client2Connected = await client2.login()
    chai.expect(client1Connected).to.be.true
    chai.expect(client2Connected).to.be.true
  })

  it('it should send and receive events when the storage is updated', async function () {
    const storages = [
      randomBytes(1024),
      randomBytes(20480),
      randomBytes(5242880) // 5 Mbytes
    ]
    const msgLimit = storages.length

    const client2promise = new Promise<void>((resolve, reject) => {
      let receivedEvents = 0
      client2.on(client2.defaultEvents['storage-updated'], (timestamp: number) => {
        console.log(`Client ${client2.name} received storage-updated event. Downloading`)
        client2.getStorage().then(storage => {
          if (storage === null) {
            reject(new Error('could not download storage'))
            return
          }
          if (storages[receivedEvents].compare(storage.storage) !== 0) {
            reject(new Error('remote storage does not equal the uploaded one'))
            return
          }
          receivedEvents++
          if (receivedEvents === msgLimit) {
            resolve()
          }
        }).catch(error => reject(error))
      })
    })

    let updated: boolean = false
    for (let i = 0; i < msgLimit; i++) {
      await setTimeout(1000)
      updated = await client1.updateStorage({
        storage: storages[i],
        timestamp: client1.timestamp
      })
      console.log(`Client ${client1.name} storage updated: ${updated.toString()}`)
      chai.expect(updated).to.be.true
    }

    await client2promise.catch((reason) => {
      console.log(reason)
      expect(false).to.be.true
    })
    expect(true).to.be.true
  })
  it('should delete all data from user if requested', async function () {
    const deleted = await client1.deleteStorage()
    chai.expect(deleted).to.be.true
  })
})
