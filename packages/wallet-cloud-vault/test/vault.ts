/* eslint-disable @typescript-eslint/no-unused-expressions */

import { expect, request, use } from 'chai'
import chaiHttp from 'chai-http'
import { Server } from 'http'
import serverPromise from '../src'
import { server as serverConfig, apiVersion } from '../src/config'
import { OpenApiPaths } from '../types/openapi'
import { UPDATE_MSG } from '../src/vault'

use(chaiHttp)

describe('Wallet Cloud-Vault: Vault Events', function () {
  this.timeout(20000) // ms

  let server: Server

  this.beforeAll(async () => {
    server = await serverPromise
  })

  this.afterAll((done) => {
    server.close((err) => {
      done(err)
    })
  })

  describe(`Testing /api/${apiVersion}/vault/events`, function () {
    it('it should send and receive events', async function (done) {
      const sseEndpoint = serverConfig.url + `/api/${apiVersion}/vault/events`
      console.log(sseEndpoint)
      const es = new EventSource(sseEndpoint)
      console.log(es.url)

      let msgCount = 0
      es.onmessage = (e) => {
        console.log(e.data)
        const msg = JSON.parse(e.data) as UPDATE_MSG
        expect(msg.code).to.equal(0)
        msgCount++
        if (msgCount === 2) {
          es.close()
          done()
        }
      }

      const updatedStorage: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
        jwe: 'RraFbEXzRKeb6-LVOS1ejNKKR7CS34_eGvQC9luVpvBUxvb5Ul7SMnS3_g-BIrTrhiK0AlMdCIuCJoMQd2SISHY.As9nW9zmGHUgwKikL8m-IfoyTWHmlAAUYfBom14g_GGH940vyxXiXulpSs8uSJNeP8-DquuqozZnGFSgsj9tnxS.1W1FkvVm6ZD0ZguaQHmoQ96zDODBgLMbqCPhFqGLNwf7c.l-F5VoevEez3AiTJDu7oUWnwYgK6Gs9QvrKbxzJOsRKToW2Ha2slS1Dze5OYINaa6rq44Y1tS7m8WDg1s-v.blFNOdNWXFu-xlw-ms_KAFd1WWE6UgGos9ZkHIeSZT8Cu98nU_pk48IC9J5P5y24S0ohU6BaArxl-_dHngPNABE9zA21l',
        timestamp: Date.now()
      }
      const res = await request(serverConfig.url)
        .post(`/api/${apiVersion}/vault`)
        .set('content-type', 'application/json')
        .send(updatedStorage)
        .end(function (error, response) {
          if (error != null) {
            done(error)
          } else {
            done()
          }
        })
      console.log(res.body)
      const res2 = await request(serverConfig.url)
        .post(`/api/${apiVersion}/vault`)
        .set('content-type', 'application/json')
        .send(updatedStorage)
        .end(function (error, response) {
          if (error != null) {
            done(error)
          } else {
            done()
          }
        })
      console.log(res2.body)
    })
  })
})
