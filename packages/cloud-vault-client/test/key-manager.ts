/* eslint-disable @typescript-eslint/no-unused-expressions */
import { KeyManager, SecretKey } from '#pkg'

describe('KeyManager', function () {
  this.timeout(30000) // ms
  let keyManager: KeyManager
  const conf = {
    username: 'testUser',
    password: 'myverystrongpassword',
    serverId: 'mysuperserver'
  }

  before('should create the key manager', async function () {
    keyManager = new KeyManager(conf.username, conf.password, {
      master: {
        salt_pattern: 'master' + conf.serverId + '{username}',
        salt_hashing_algorithm: 'sha3-512',
        input: 'password',
        alg: 'scrypt',
        derived_key_length: 32,
        alg_options: {
          N: 2 ** 21,
          r: 8,
          p: 1
        }
      },
      auth: {
        salt_pattern: 'auth' + conf.serverId + '{username}',
        salt_hashing_algorithm: 'sha3-512',
        input: 'master-key',
        alg: 'scrypt',
        derived_key_length: 32,
        alg_options: {
          N: 2 ** 16,
          r: 8,
          p: 1
        }
      },
      enc: {
        salt_pattern: 'enc' + conf.serverId + '{username}',
        salt_hashing_algorithm: 'sha3-512',
        input: 'master-key',
        alg: 'scrypt',
        derived_key_length: 32,
        enc_algorithm: 'aes-256-gcm',
        alg_options: {
          N: 2 ** 16,
          r: 8,
          p: 1
        }
      }
    })

    await keyManager.initialized

    chai.expect(true)
  })

  it('it should return the auth key as a string', async function () {
    const authKey = keyManager.authKey
    console.log(authKey)
    chai.expect(authKey).to.be.a('string')
  })

  it('it should return the enc key as a KeyObject', async function () {
    const encKey = keyManager.encKey
    console.log(encKey)
    chai.expect(encKey).to.be.an.instanceof(SecretKey)
  })
})
