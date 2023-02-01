/* eslint-disable @typescript-eslint/no-unused-expressions */
import { KeyManager } from '#pkg'
import { KeyObject } from 'node:crypto'

describe('KeyManager', function () {
  this.timeout(30000) // ms
  let keyManager: KeyManager
  const conf = {
    username: 'testUser',
    password: 'myverystrongpassword',
    serverId: 'mysuperserver'
  }

  before('should create the key manager', async function () {
    keyManager = new KeyManager('mysuperpassword', {
      master: {
        salt: 'master' + conf.serverId + conf.username,
        alg: 'scrypt',
        derivedKeyLength: 32,
        algOptions: {
          N: 2 ** 21
        }
      },
      auth: {
        salt: 'auth',
        alg: 'scrypt',
        derivedKeyLength: 32
      },
      enc: {
        salt: 'enc',
        alg: 'scrypt',
        derivedKeyLength: 32
      }
    })

    await keyManager.initialized

    chai.expect(true)
  })

  it('it should return the auth key as a string', async function () {
    const authKey = await keyManager.getAuthKey()
    console.log(authKey)
    chai.expect(authKey).to.be.a('string')
  })

  it('it should return the enc key as a KeyObject', async function () {
    const encKey = await keyManager.getEncKey()
    console.log(encKey)
    chai.expect(encKey).to.be.an.instanceof(KeyObject)
  })
})
