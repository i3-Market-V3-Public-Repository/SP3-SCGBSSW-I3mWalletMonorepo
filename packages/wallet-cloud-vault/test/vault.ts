/* eslint-disable @typescript-eslint/no-unused-expressions */

import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { Server } from 'http'
import serverPromise from '../src'
import { server as serverConfig, apiVersion } from '../src/config'
import { OpenApiPaths } from '../types/openapi'
import { UPDATE_MSG } from '../src/vault'
import EventSource from 'eventsource'

use(chaiHttp)

describe('Wallet Cloud-Vault: Vault Events', function () {
  this.timeout(20000) // ms

  let server: Server

  before(async () => {
    server = await serverPromise
  })

  after(done => {
    server.close((err) => {
      done(err)
    })
  })

  describe(`Testing /api/${apiVersion}/vault/events`, function () {
    it('it should send and receive events', async function () {
      const sseEndpoint = serverConfig.url + `/api/${apiVersion}/vault/events`
      const es1 = new EventSource(sseEndpoint)
      const es2 = new EventSource(sseEndpoint)
      console.log(es1.url)

      const msgLimit = 7

      await new Promise<void>((resolve, reject) => {
        let es1MsgCount = 0
        let oneFinished = false
        es1.onmessage = (e) => {
          const msg = JSON.parse(e.data) as UPDATE_MSG
          console.log('client 1:', msg)
          es1MsgCount++
          if (es1MsgCount === msgLimit) {
            es1.close()
            expect(true)
            if (oneFinished) resolve()
            else oneFinished = true
          }
        }

        let es2MsgCount = 0
        es2.onmessage = (e) => {
          const msg = JSON.parse(e.data) as UPDATE_MSG
          console.log('client 2:', msg)
          es2MsgCount++
          if (es2MsgCount === msgLimit) {
            es2.close()
            expect(true)
            if (oneFinished) resolve()
            else oneFinished = true
          }
        }

        es1.onerror = function (err) {
          if (err != null) {
            if (err.status === 401 || err.status === 403) {
              console.log('not authorized')
            }
          }
          es1.close()
          reject(err)
        }

        es2.onerror = function (err) {
          if (err != null) {
            if (err.status === 401 || err.status === 403) {
              console.log('not authorized')
            }
          }
          es2.close()
          reject(err)
        }

        for (let i = 0; i < msgLimit; i++) {
          const updatedStorage: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
            jwe: 'RraFbEXzRKeb6-LVOS1ejNKKR7CS34_eGvQC9luVpvBUxvb5Ul7SMnS3_g-BIrTrhiK0AlMdCIuCJoMQd2SISHY.As9nW9zmGHUgwKikL8m-IfoyTWHmlAAUYfBom14g_GGH940vyxXiXulpSs8uSJNeP8-DquuqozZnGFSgsj9tnxS.1W1FkvVm6ZD0ZguaQHmoQ96zDODBgLMbqCPhFqGLNwf7c.l-F5VoevEez3AiTJDu7oUWnwYgK6Gs9QvrKbxzJOsRKToW2Ha2slS1Dze5OYINaa6rq44Y1tS7m8WDg1s-v.blFNOdNWXFu-xlw-ms_KAFd1WWE6UgGos9ZkHIeSZT8Cu98nU_pk48IC9J5P5y24S0ohU6BaArxl-_dHngPNABE9zA21l',
            timestamp: (i === msgLimit - 1) ? 0 : Date.now()
          }

          request(serverConfig.url)
            .post(`/api/${apiVersion}/vault`)
            .set('content-type', 'application/json')
            .send(updatedStorage)
            .then(res => {
              console.log(res.body)
            })
            .catch(err => {
              reject(err)
            })
        }
      })
    })
  })
})
