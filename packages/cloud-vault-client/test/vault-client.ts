/* eslint-disable @typescript-eslint/no-unused-expressions */
import { VaultClient, VaultError } from '#pkg'
import { setTimeout as timersSetTimeout } from 'timers'
import { promisify } from 'util'
import { Server } from '@i3m/cloud-vault-server'
import { spawn } from 'child_process'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import { importJwk, jweEncrypt, JWK } from '@i3m/non-repudiation-library'
import { config as loadEnvFile } from 'dotenv'
import axios, { AxiosError } from 'axios'
import { randomBytes } from 'crypto'
import { expect } from 'chai'
import { join as pathJoin } from 'path'

loadEnvFile()

const setTimeout = promisify(timersSetTimeout)

let serverUrl: string, username: string, password: string
let localTesting: boolean

if (process.env.WCV_SERVER_URL === undefined || process.env.WCV_USERNAME === undefined || process.env.WCV_PASSWORD === undefined) {
  console.log('No server setup provided. Using local testing server. You need docker and docker compose for it to work')
  serverUrl = 'http://localhost:3000'
  username = 'testUser'
  password = 'mysuperpassword'
  localTesting = true
} else {
  serverUrl = process.env.WCV_SERVER_URL
  username = process.env.WCV_USERNAME
  password = process.env.WCV_PASSWORD
  localTesting = false
}

const user = {
  did: 'did:ethr:i3m:0x02c1e51dbe7fa3c3e89df33495f241316d9554b5206fcef16d8108486285e38c27',
  username,
  password
}

const apiVersion: string = 'v' + (process.env.npm_package_version?.split('.')[0] ?? '2')

async function runCommand (cmd: string, args: string[]): Promise<{ code: number | null, stdout: string, stderr: string }> {
  const command = spawn(cmd, args, {
    cwd: pathJoin(__dirname, '..', '..', 'node_modules', '@i3m', 'cloud-vault-server', 'test', 'postgresql'),
    env: {
      DB_HOST: '127.0.0.1',
      DB_PORT: '25432',
      DB_NAME: 'myuser',
      DB_USER: 'myuser',
      DB_PASSWORD: 'mysuperpassword'
    }
  })

  let stdout = ''
  let stderr = ''
  command.stdout.on('data', data => {
    stdout += data as string
  })

  command.stderr.on('data', data => {
    stderr += data as string
  })

  return await new Promise((resolve, reject) => {
    command.on('error', (error) => {
      console.log(stderr)
      reject(error)
    })
    command.on('close', code => {
      resolve({
        code,
        stderr,
        stdout
      })
    })
  })
}
async function runLocalDb (): Promise<void> {
  // let { code, stderr, stdout } = await runCommand('sudo', ['systemctl', 'start', 'docker'])
  // console.log(code, stdout, stderr);
  let { code, stderr, stdout } = await runCommand('docker', ['compose', 'up', '-d'])
  console.log(code, stdout, stderr);
  ({ code, stderr, stdout } = await runCommand('sleep', ['3']))
  console.log(code, stdout, stderr)
}

async function stopLocalDb (): Promise<void> {
  const { code, stderr, stdout } = await runCommand('docker', ['compose', 'down'])
  console.log(code, stdout, stderr)
}

describe('Wallet Cloud-Vault', function () {
  this.timeout(30000) // ms
  let client1: VaultClient
  let client2: VaultClient
  let publicJwk: OpenApiComponents.Schemas.JwkEcPublicKey

  before('should connect two clients to the Cloud Vault Server and get the server\'s public key', async function () {
    if (localTesting) {
      await runLocalDb()
      try {
        const { serverPromise } = await import('@i3m/cloud-vault-server')
        const server: Server = await serverPromise
        this.server = server
        await server.dbConnection.db.initialized
      } catch (error) {
        console.log(error)
        console.log('\x1b[91mALL TEST SKIPPED: A connection to a DB has not been setup\x1b[0m')
        this.skip()
      }
    }

    client1 = new VaultClient(serverUrl, '1')
    client2 = new VaultClient(serverUrl, '2')

    client1.on('connection-error', error => {
      console.log(client1.name, ': ', error)
    })
    client2.on('connection-error', error => {
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
    client1.logout()
    client2.logout()

    if (localTesting) {
      const server: Server | undefined = this.server
      if (server !== undefined && server.server.listening) { // eslint-disable-line @typescript-eslint/prefer-optional-chain
        server.server.closeAllConnections()
        server.server.close((err) => {
          done(err)
        })
      } else {
        done()
      }
      stopLocalDb().then(() => {
        done()
      }).catch((err) => {
        done(err)
      })
    } else {
      done()
    }
  })

  it('it should register the test user', async function () {
    try {
      const userData = {
        did: user.did,
        username: user.username,
        authkey: await VaultClient.computeAuthKey(serverUrl, user.username, user.password)
      }
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify(userData)),
        publicJwk as JWK,
        'A256GCM'
      )
      const res = await axios.get<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.Responses.$201>(
        serverUrl + `/api/${apiVersion}/registration/register/` + data
      )
      chai.expect(res.status).to.equal(201)
    } catch (error) {
      if (error instanceof AxiosError) {
        console.log('error', error.response?.data)
      } else {
        console.log('error', error)
      }
      chai.expect(false).to.be.true
    }
  })

  it('it should fail registering the same user again', async function () {
    try {
      const userData = {
        did: user.did,
        username: user.username,
        authkey: await VaultClient.computeAuthKey(serverUrl, user.username, user.password)
      }
      const data = await jweEncrypt(
        Buffer.from(JSON.stringify(userData)),
        publicJwk as JWK,
        'A256GCM'
      )
      await axios.get<OpenApiPaths.ApiV2RegistrationRegister$Data.Get.Responses.$400>(
        serverUrl + `/api/${apiVersion}/registration/register/` + data
      )
    } catch (error) {
      if (error instanceof AxiosError) {
        const response = error.response
        chai.expect(response?.status).to.equal(400)
      } else {
        console.log('error', error)
        chai.expect(false).to.be.true
      }
    }
  })

  it('trying to log in with invalid credentials fails', async function () {
    let clientConnected = false
    try {
      await client1.login(user.username, 'badpassword')
      clientConnected = true
    } catch (error) {}
    chai.expect(clientConnected).to.be.false
  })

  it('trying to get storage fails if not logged in', async function () {
    const storage = await client1.getStorage().catch(() => {})
    chai.expect(storage).to.be.undefined
  })

  it('should be able to connect to server using registered credentials', async function () {
    let clientsConnected = false
    try {
      await client1.login(user.username, user.password)
      await client2.login(user.username, user.password)
      clientsConnected = true
    } catch (error) {}
    chai.expect(clientsConnected).to.be.true
  })

  it('should fail getting storage if not previously uploaded', async function () {
    const storage = await client1.getStorage().catch((err) => {
      expect(err).to.be.an.instanceOf(VaultError)
      expect((err as VaultError).message).to.equal('no-uploaded-storage')
    })
    expect(storage).to.be.undefined
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
      client2.on('storage-updated', (timestamp: number) => {
        console.log(`Client ${client2.name} received storage-updated event. Downloading...`)
        client2.getStorage().then(storage => {
          if (storages[receivedEvents].compare(storage.storage) !== 0) {
            reject(new Error('remote storage does not equal the uploaded one'))
            return
          }
          console.log(`Client ${client2.name}: downloading done`)
          receivedEvents++
          if (receivedEvents === msgLimit) {
            resolve()
          }
        }).catch(error => reject(error))
      })
    })

    for (let i = 0; i < msgLimit; i++) {
      await setTimeout(1000)
      let updated = false
      try {
        await client1.updateStorage({
          storage: storages[i],
          timestamp: client1.timestamp
        })
        updated = true
      } catch (error) {
        console.log(error)
      }
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
    let deleted = true
    await client1.deleteStorage().catch(error => {
      console.log(error)
      deleted = false
    })
    chai.expect(deleted).to.be.true
  })
})
