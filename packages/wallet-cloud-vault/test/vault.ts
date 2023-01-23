/* eslint-disable @typescript-eslint/no-unused-expressions */

import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import EventSource from 'eventsource'
import { apiVersion, server as serverConfig } from '../src/config'
import { UPDATE_MSG } from '../src/vault'
import { OpenApiComponents, OpenApiPaths } from '../types/openapi'
import { setTimeout } from 'timers/promises'

use(chaiHttp)

const vaultPath = `/api/${apiVersion}/vault`
const vaultUrl = serverConfig.url + vaultPath

class Client {
  timestamp?: number
  token: string
  msgCount: number
  name: string
  closed: Promise<void>

  constructor (vaultUrl: string, token: string, msgLimit: number, name?: string) {
    this.name = name ?? 'no name'
    this.msgCount = 0
    this.token = token

    const sseEndpoint = vaultUrl + '/events'

    const es = new EventSource(sseEndpoint, {
      headers: {
        Authorization: 'Bearer ' + token
      }
    })
    this.closed = new Promise((resolve, reject) => {
      es.onmessage = (e) => {
        const msg = JSON.parse(e.data) as UPDATE_MSG
        if (msg.timestamp !== undefined) this.timestamp = msg.timestamp
        this.msgCount++
        console.log(`client ${this.name} - msg ${this.msgCount}: `, msg)
        if (this.msgCount === msgLimit) {
          es.close()
          resolve()
        }
      }
      es.onerror = (err) => {
        console.log(`[ERROR]: client ${this.name}: `, err)
        reject(err)
      }
    })
  }

  async updateStorage (): Promise<boolean> {
    const updatedStorage: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
      jwe: 'RraFbEXzRKeb6-LVOS1ejNKKR7CS34_eGvQC9luVpvBUxvb5Ul7SMnS3_g-BIrTrhiK0AlMdCIuCJoMQd2SISHY.As9nW9zmGHUgwKikL8m-IfoyTWHmlAAUYfBom14g_GGH940vyxXiXulpSs8uSJNeP8-DquuqozZnGFSgsj9tnxS.1W1FkvVm6ZD0ZguaQHmoQ96zDODBgLMbqCPhFqGLNwf7c.l-F5VoevEez3AiTJDu7oUWnwYgK6Gs9QvrKbxzJOsRKToW2Ha2slS1Dze5OYINaa6rq44Y1tS7m8WDg1s-v.blFNOdNWXFu-xlw-ms_KAFd1WWE6UgGos9ZkHIeSZT8Cu98nU_pk48IC9J5P5y24S0ohU6BaArxl-_dHngPNABE9zA21l',
      timestamp: this.timestamp
    }

    const oldTimestamp = this.timestamp
    const res = await request(serverConfig.url)
      .post(vaultPath)
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + this.token)
      .send(updatedStorage)

    this.timestamp = (res.body as OpenApiPaths.ApiV2Vault.Post.Responses.$201).timestamp
    return this.timestamp !== oldTimestamp
  }
}

describe('Wallet Cloud-Vault: Vault Events', function () {
  this.timeout(30000) // ms
  let token: string

  before(`should get a token if posting valid credentials to ${vaultPath}/auth`, async function () {
    const credentials: OpenApiComponents.Schemas.AuthorizationRequest = {
      username: 'testUser',
      authkey: 'uvATmXpCml3YNqyQ-w3CtJfiCOkHIXo4uUAEj4oshGQ'
    }
    const res = await request(serverConfig.url)
      .post(`${vaultPath}/auth`)
      .set('content-type', 'application/json')
      .send(credentials)
    expect(res.body.token).to.not.be.undefined
    token = res.body.token
  })

  describe(`Testing /api/${apiVersion}/vault/events`, function () {
    it('it should send and receive events', async function () {
      const msgLimit = 6

      const client1 = new Client(vaultUrl, token, msgLimit, '1')
      const client2 = new Client(vaultUrl, token, msgLimit, '2')

      for (let i = 0; i < msgLimit; i++) {
        await setTimeout(1000)
        try {
          const updated = await client1.updateStorage()
          console.log(`Client ${client1.name} storage updated: ${updated.toString()}`)
        } catch (error) {
          console.log(error)
        }
      }

      await Promise.all([client1.closed, client2.closed])
    })
  })
})
