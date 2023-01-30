/* eslint-disable @typescript-eslint/no-unused-expressions */

import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { randomBytes } from 'crypto'
import EventSource from 'eventsource'
import { setTimeout } from 'timers/promises'
import { apiVersion } from '../src/config/openApi'
import { server as serverConfig } from '../src/config/server'
import { STORAGE_UPDATED_EVENT } from '../src/vault'
import type { OpenApiComponents, OpenApiPaths } from '../types/openapi'

use(chaiHttp)

const vaultPath = `/api/${apiVersion}/vault`

class Client {
  timestamp?: number
  token: string
  msgCount: number
  name: string
  serverUrl: string

  private readonly es: EventSource
  private readonly closeEvent: Event

  constructor (serverUrl: string, token: string, name?: string) {
    this.serverUrl = serverUrl

    const vaultUrl = serverUrl + vaultPath

    this.name = name ?? randomBytes(16).toString('hex')
    this.msgCount = 0
    this.token = token

    this.closeEvent = new Event('close')

    const sseEndpoint = vaultUrl + '/events'

    this.es = new EventSource(sseEndpoint, {
      headers: {
        Authorization: 'Bearer ' + token
      }
    })

    this.es.addEventListener('storage-updated', (e) => {
      const msg = JSON.parse(e.data) as STORAGE_UPDATED_EVENT['data']
      if (msg.timestamp !== undefined) this.timestamp = msg.timestamp
      this.msgCount++
      console.log(`client ${this.name} - msg ${this.msgCount}: `, msg)
    })

    this.es.onerror = (err) => {
      console.log(`[ERROR]: client ${this.name}: `, err)
    }
    this.es.addEventListener('close', (e) => {
      console.log(`client ${this.name}: closing`)
      this.es.close()
    })
  }

  close (): void {
    this.es.dispatchEvent(this.closeEvent)
  }

  async updateStorage (): Promise<boolean> {
    const updatedStorage: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
      jwe: 'RraFbEXzRKeb6-LVOS1ejNKKR7CS34_eGvQC9luVpvBUxvb5Ul7SMnS3_g-BIrTrhiK0AlMdCIuCJoMQd2SISHY.As9nW9zmGHUgwKikL8m-IfoyTWHmlAAUYfBom14g_GGH940vyxXiXulpSs8uSJNeP8-DquuqozZnGFSgsj9tnxS.1W1FkvVm6ZD0ZguaQHmoQ96zDODBgLMbqCPhFqGLNwf7c.l-F5VoevEez3AiTJDu7oUWnwYgK6Gs9QvrKbxzJOsRKToW2Ha2slS1Dze5OYINaa6rq44Y1tS7m8WDg1s-v.blFNOdNWXFu-xlw-ms_KAFd1WWE6UgGos9ZkHIeSZT8Cu98nU_pk48IC9J5P5y24S0ohU6BaArxl-_dHngPNABE9zA21l',
      timestamp: this.timestamp
    }

    const oldTimestamp = this.timestamp
    const res = await request(this.serverUrl)
      .post(vaultPath)
      .set('content-type', 'application/json')
      .set('Authorization', 'Bearer ' + this.token)
      .send(updatedStorage)

    if (res.status !== 201) return false
    this.timestamp = (res.body as OpenApiPaths.ApiV2Vault.Post.Responses.$201).timestamp
    return this.timestamp !== oldTimestamp
  }

  async deleteStorage (): Promise<ChaiHttp.Response> {
    return await request(this.serverUrl)
      .delete(vaultPath)
      .set('Authorization', 'Bearer ' + this.token)
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
    expect(res).to.have.status(200)
    expect(res.body.token).to.not.be.undefined
    token = res.body.token
  })

  describe(`Testing /api/${apiVersion}/vault/events`, function () {
    let client1: Client
    let client2: Client

    it('it should send and receive events', async function () {
      const msgLimit = 6

      client1 = new Client(serverConfig.url, token, '1')
      client2 = new Client(serverConfig.url, token, '2')

      let updated: boolean = false
      for (let i = 0; i < msgLimit; i++) {
        await setTimeout(1000)
        try {
          updated = await client1.updateStorage()
          console.log(`Client ${client1.name} storage updated: ${updated.toString()}`)
        } catch (error) {
          console.log(error)
        }
        expect(updated).to.be.true
      }

      client1.close()
      client2.close()
    })
    it('should delete all data from user if requested', async function () {
      const res = await client1.deleteStorage()
      expect(res).to.have.status(204)
    })
  })
})
