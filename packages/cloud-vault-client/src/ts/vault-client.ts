import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import { Request, RetryOptions } from './request'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import EventSource from 'eventsource'
import { apiVersion } from './config'
import { VaultError } from './error'
import { KeyManager } from './key-manager'

import type { ArgsForEvent, VaultEventName } from './events'
import { VAULT_STATE, VaultState, stateFromError } from './vault-state'

export type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void

export interface VaultStorage {
  storage: Buffer
  timestamp?: number // milliseconds elapsed since epoch of the last downloaded storage
}

export interface VaultClientOpts {
  name?: string
  defaultRetryOptions?: RetryOptions
}

interface LoginOptions {
  username: string
  password: string
  timestamp?: number
}

export class VaultClient extends EventEmitter {
  timestamp?: number
  token?: string
  name: string
  opts?: VaultClientOpts
  serverRootUrl: string
  serverPrefix: string
  serverUrl: string

  initialized: Promise<void>

  private wellKnownCvsConfigurationPromise?: {
    promise: Promise<OpenApiComponents.Schemas.CvsConfiguration>
    stop: () => void
  }

  wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration

  state: Promise<VaultState>

  private vaultRequest?: Request
  private keyManager?: KeyManager

  private es?: EventSource

  constructor (serverUrl: string, opts?: VaultClientOpts) {
    super({ captureRejections: true })

    this.name = opts?.name ?? randomBytes(16).toString('hex')
    this.opts = opts
    const url = new URL(serverUrl)
    this.serverRootUrl = url.origin
    this.serverPrefix = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname
    this.serverUrl = this.serverRootUrl + this.serverPrefix

    this.state = new Promise((resolve, reject) => {
      resolve(VAULT_STATE.NOT_INITIALIZED)
    })

    this.initialized = new Promise((resolve, reject) => {
      this.state.then((state) => {
        this.switchToState(VAULT_STATE.INITIALIZED).then(() => {
          resolve()
        })
          .catch((err) => {
            reject(err)
            this.state = new Promise((resolve, reject) => {
              resolve(VAULT_STATE.NOT_INITIALIZED)
            })
          })
      }).catch(error => {
        reject(error)
      })
    })
  }

  emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean {
    return super.emit(eventName, ...args)
  }

  on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(eventName, listener)
  }

  once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this
  once (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.once(eventName, listener)
  }

  protected async switchToState (newState: VaultState, opts?: LoginOptions): Promise<VaultState> {
    let currentState = await this.state
    if (currentState === newState) return currentState

    if (newState < VAULT_STATE.NOT_INITIALIZED || newState > VAULT_STATE.CONNECTED) {
      throw new Error('invalid state')
    }

    while (newState - currentState > 1) {
      currentState = await this.switchToState(currentState + 1 as VaultState, opts)
    }
    while (currentState - newState > 1) {
      currentState = await this.switchToState(currentState - 1 as VaultState, opts)
    }

    this.state = new Promise((resolve, reject) => {
      this._switchToState(currentState, newState, opts).then((state) => {
        resolve(state)
        this.emit('state-changed', state)
      }).catch(err => {
        console.log(err)
        resolve(currentState)
      })
    })

    return await this.state
  }

  private async _switchToState (currentState: VaultState, newState: VaultState, opts?: LoginOptions): Promise<VaultState> {
    switch (newState) {
      case VAULT_STATE.NOT_INITIALIZED:
        // Only option is to come from INITIALIZED
        this.wellKnownCvsConfigurationPromise?.stop()
        await this.wellKnownCvsConfigurationPromise?.promise.catch()
        delete this.wellKnownCvsConfigurationPromise
        delete this.wellKnownCvsConfiguration

        this.state = new Promise((resolve, reject) => {
          resolve(VAULT_STATE.NOT_INITIALIZED)
        })
        break

      case VAULT_STATE.INITIALIZED:
        if (currentState === VAULT_STATE.NOT_INITIALIZED) {
          this.wellKnownCvsConfigurationPromise = VaultClient.getWellKnownCvsConfiguration(this.serverRootUrl + this.serverPrefix, {
            retries: 1200 * 24, // will retry for 24 hours
            retryDelay: 3000
          })

          this.wellKnownCvsConfiguration = await this.wellKnownCvsConfigurationPromise.promise.catch(err => {
            throw new VaultError('not-initialized', err)
          })
        } else { // this.state === VAULT_STATE.LOGGED_IN
          await this.vaultRequest?.stop()
          delete this.vaultRequest

          delete this.token
          delete this.timestamp
          delete this.keyManager

          this.es?.close()
          delete this.es
        }
        break

      case VAULT_STATE.LOGGED_IN:
        if (currentState === VAULT_STATE.INITIALIZED) {
          if (opts === undefined || opts.username === undefined || opts.password === undefined) {
            throw new VaultError('invalid-credentials', new Error('you need credentials to log in'))
          }

          await this._initKeyManager(opts.username, opts.password)

          const reqBody: OpenApiPaths.ApiV2VaultToken.Post.RequestBody = {
            username: opts.username,
            authkey: (this.keyManager as KeyManager).authKey
          }

          const request = new Request({ retryOptions: this.opts?.defaultRetryOptions })
          const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

          const data = await request.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
            cvsConf.vault_configuration.v2.token_endpoint,
            reqBody,
            { responseStatus: 200 }
          )

          this.token = data.token

          this.vaultRequest = new Request({
            retryOptions: this.opts?.defaultRetryOptions,
            defaultCallOptions: {
              bearerToken: this.token,
              sequential: true
            },
            defaultUrl: cvsConf.vault_configuration.v2.vault_endpoint
          })

          this.timestamp = opts.timestamp
        } else { // this.state === VAULT_STATE.CONNECTED
          this.es?.close()
          delete this.es
        }
        break

      case VAULT_STATE.CONNECTED:
        // this.state === VAULT_STATE.LOGGED_IN
        await this._initEventSourceClient()
        break

      default:
        break
    }
    return newState
  }

  private async _initEventSourceClient (): Promise<void> {
    return await new Promise((resolve, reject) => {
      try {
        const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
        const esUrl = cvsConf.vault_configuration[apiVersion].events_endpoint
        this.es = new EventSource(esUrl, {
          headers: {
            Authorization: 'Bearer ' + (this.token as string)
          }
        })

        this.es.addEventListener('connected', (e) => {
          const msg = JSON.parse(e.data) as ConnectedEvent['data']
          if (msg.timestamp === undefined) {
            this.emit('empty-storage')
          } else if (msg.timestamp !== this.timestamp) {
            this.timestamp = msg.timestamp
            this.emit('storage-updated', this.timestamp)
          }
          resolve()
        })

        this.es.addEventListener('storage-updated', (e) => {
          const vaultRequest = this.vaultRequest as Request
          vaultRequest.waitForOngoingRequestsToFinsh().finally(() => {
            const msg = JSON.parse(e.data) as StorageUpdatedEvent['data']
            if (msg.timestamp !== this.timestamp) {
              this.timestamp = msg.timestamp
              this.emit('storage-updated', this.timestamp)
            }
          }).catch(reason => {})
        })

        this.es.addEventListener('storage-deleted', (e) => {
          const vaultRequest = this.vaultRequest as Request
          vaultRequest.waitForOngoingRequestsToFinsh().finally(() => {
            this.logout().catch(err => { throw err })
            this.emit('storage-deleted')
          }).catch(reason => {})
        })

        this.es.onerror = (e) => {
          this.state.then((state) => {
            this.switchToState(stateFromError(state, e)).catch((reason) => {
              console.error(reason)
            })
          }).catch(reason => {
            console.error(reason)
          })
        }
      } catch (error) {
        reject(error)
      }
    })
  }

  private async _initKeyManager (username: string, password: string): Promise<void> {
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    this.keyManager = new KeyManager(username, password, cvsConf.vault_configuration[apiVersion].key_derivation)
    await this.keyManager.initialized
  }

  async login (username: string, password: string, timestamp?: number): Promise<void> {
    await this.initialized
    await this.switchToState(VAULT_STATE.CONNECTED, {
      username,
      password,
      timestamp
    })
  }

  async logout (): Promise<void> {
    await this.switchToState(VAULT_STATE.INITIALIZED)
  }

  async close (): Promise<void> {
    await this.switchToState(VAULT_STATE.NOT_INITIALIZED)
  }

  async getRemoteStorageTimestamp (): Promise<number | null> {
    if (await this.state !== VAULT_STATE.LOGGED_IN) {
      throw new VaultError('unauthorized', new Error('you must be logged in'))
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    try {
      await (this.vaultRequest as Request).waitForOngoingRequestsToFinsh()
      const request = new Request({ retryOptions: this.opts?.defaultRetryOptions })
      const data = await request.get<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>(
        cvsConf.vault_configuration[apiVersion].timestamp_endpoint,
        {
          bearerToken: this.token,
          responseStatus: 200
        }
      )

      if ((this.timestamp ?? 0) < data.timestamp) {
        this.timestamp = data.timestamp
      }

      return data.timestamp
    } catch (error) {
      await this.switchToState(stateFromError(await this.state, error))
      throw error
    }
  }

  async getStorage (): Promise<VaultStorage> {
    if (await this.state < VAULT_STATE.LOGGED_IN) {
      throw new VaultError('unauthorized', undefined)
    }
    const startTs = Date.now()
    this.emit('sync-start', startTs)

    try {
      const vaultRequest = this.vaultRequest as Request

      await vaultRequest.waitForOngoingRequestsToFinsh()

      const data = await vaultRequest.get<OpenApiPaths.ApiV2Vault.Get.Responses.$200>(
        {
          bearerToken: this.token,
          responseStatus: 200
        }
      )

      if (data.timestamp < (this.timestamp ?? 0)) {
        throw new VaultError('validation', {
          description: 'WEIRD!!! Received timestamp is older than the one received in previous events'
        })
      }
      const storage = (this.keyManager as KeyManager).encKey.decrypt(Buffer.from(data.ciphertext, 'base64url'))
      this.timestamp = data.timestamp

      this.emit('sync-stop', startTs, Date.now())

      return {
        storage,
        timestamp: data.timestamp
      }
    } catch (error) {
      this.emit('sync-stop', startTs, Date.now())
      await this.switchToState(stateFromError(await this.state, error))
      throw VaultError.from(error)
    }
  }

  async updateStorage (storage: VaultStorage, force: boolean = false, retryOptions?: RetryOptions): Promise<number> {
    if (await this.state < VAULT_STATE.LOGGED_IN) {
      throw new VaultError('unauthorized', undefined)
    }

    const startTs = Date.now()
    this.emit('sync-start', startTs)

    try {
      if (force) {
        const remoteTimestamp = await this.getRemoteStorageTimestamp()
        storage.timestamp = (remoteTimestamp !== null) ? remoteTimestamp : undefined
      }

      if (this.timestamp !== undefined && (storage.timestamp ?? 0) < this.timestamp) {
        throw new VaultError('conflict', {
          localTimestamp: storage.timestamp,
          remoteTimestamp: this.timestamp
        })
      }

      const encryptedStorage = (this.keyManager as KeyManager).encKey.encrypt(storage.storage)

      const requestBody: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
        ciphertext: encryptedStorage.toString('base64url'),
        timestamp: storage.timestamp
      }

      const vaultRequest = this.vaultRequest as Request
      const data = await vaultRequest.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(requestBody, {
        bearerToken: this.token,
        responseStatus: 201,
        beforeRequestFinish: async (data) => {
          this.timestamp = data.timestamp
        }
      })

      this.emit('sync-stop', startTs, Date.now())

      return data.timestamp
    } catch (error) {
      this.emit('sync-stop', startTs, Date.now())
      await this.switchToState(stateFromError(await this.state, error))
      throw VaultError.from(error)
    }
  }

  async deleteStorage (): Promise<void> {
    if (await this.state < VAULT_STATE.LOGGED_IN) {
      throw new VaultError('unauthorized', new Error('you must be logged in'))
    }

    try {
      const vaultRequest = this.vaultRequest as Request
      await vaultRequest.stop()
      await vaultRequest.delete<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
        {
          bearerToken: this.token,
          responseStatus: 204
        }
      )
      await this.logout()
    } catch (error) {
      if (error instanceof VaultError && error.message === 'unauthorized') {
        await this.logout()
      }
      throw error
    }
  }

  async getServerPublicKey (): Promise<OpenApiComponents.Schemas.JwkEcPublicKey> {
    await this.initialized.catch(err => {
      throw new VaultError('unknown', err)
    })
    const currentState = await this.state
    if (currentState === VAULT_STATE.NOT_INITIALIZED) {
      throw new VaultError('not-initialized', undefined)
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const request = new Request({ retryOptions: this.opts?.defaultRetryOptions })
    const data = await request.get<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>(
      cvsConf.registration_configuration.public_jwk_endpoint,
      { responseStatus: 200 }
    )
    return data.jwk
  }

  static getWellKnownCvsConfiguration (serverUrl: string, opts?: RetryOptions): {
    stop: () => Promise<void>
    promise: Promise<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>
  } {
    const request = new Request({ retryOptions: opts })
    const promise = request.get<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>(
      serverUrl + '/.well-known/cvs-configuration', { responseStatus: 200 })

    return {
      stop: async () => await request.stop(),
      promise
    }
  }

  static async computeAuthKey (serverUrl: string, username: string, password: string, retryOptions?: RetryOptions): Promise<string> {
    const cvsConf = VaultClient.getWellKnownCvsConfiguration(serverUrl, retryOptions)
    const opts = await cvsConf.promise
    const keyManager = new KeyManager(username, password, opts.vault_configuration[apiVersion].key_derivation)
    await keyManager.initialized
    return keyManager.authKey
  }
}
