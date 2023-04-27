import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import EventSource from 'eventsource'
import { apiVersion } from './config'
import { VaultError } from './error'
import { KeyManager } from './key-manager'
import { Request, RetryOptions } from './request'

import type { ArgsForEvent, VaultEventName } from './events'
import { VAULT_STATE, VaultState, stateFromError } from './vault-state'
import { JWK, jweEncrypt } from '@i3m/non-repudiation-library'
import { passwordCheck, PasswordStrengthOptions } from './password-checker'

export type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void

export interface VaultStorage {
  storage: Buffer
  timestamp?: number // milliseconds elapsed since epoch of the last downloaded storage
}

export interface VaultClientOpts {
  name?: string
  defaultRetryOptions?: RetryOptions
  passwordStrengthOptions?: PasswordStrengthOptions
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
  serverUrl?: string

  wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration

  state: Promise<VaultState>

  private readonly request: Request
  private keyManager?: KeyManager

  private es?: EventSource

  private switchingState: Promise<void>

  constructor (opts?: VaultClientOpts) {
    super({ captureRejections: true })

    this.name = opts?.name ?? randomBytes(16).toString('hex')

    this.request = new Request({
      retryOptions: {
        retries: 1200 * 24, // will retry for 24 hours
        retryDelay: 3000,
        ...opts?.defaultRetryOptions
      },
      defaultCallOptions: {
        sequential: true
      }
    })

    this.state = new Promise((resolve, reject) => {
      resolve(VAULT_STATE.NOT_INITIALIZED)
    })

    this.switchingState = new Promise((resolve, reject) => {
      resolve()
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
    if (newState < VAULT_STATE.LOGGED_IN) {
      await this.request.stop()
    }
    await this.switchingState
    let error: VaultError | undefined
    let state: VaultState | undefined
    this.switchingState = new Promise((resolve, reject) => {
      this._switchToStatePromise(newState, opts)
        .then((finalState) => {
          state = finalState
        })
        .catch((err) => {
          error = VaultError.from(err)
        })
        .finally(() => {
          resolve()
        })
    })
    await this.switchingState
    if (error !== undefined) {
      throw error
    }
    return state as VaultState
  }

  private async _switchToStatePromise (newState: VaultState, opts?: LoginOptions): Promise<VaultState> {
    let currentState = await this.state
    if (currentState === newState) {
      return currentState
    }

    if (newState < VAULT_STATE.NOT_INITIALIZED || newState > VAULT_STATE.CONNECTED) {
      throw new VaultError('error', new Error('invalid state'))
    }

    const i = (newState > currentState) ? 1 : -1
    while (currentState !== newState) {
      let error
      this.state = new Promise((resolve, reject) => {
        this._switchToState(currentState, currentState + i as VaultState, opts).then((state) => {
          resolve(state)
          this.emit('state-changed', state)
        }).catch((err) => {
          error = err
          resolve(currentState)
        })
      })
      currentState = await this.state
      if (error !== undefined) {
        throw VaultError.from(error)
      }
    }
    return currentState
  }

  private async _switchToState (currentState: VaultState, newState: VaultState, opts?: LoginOptions): Promise<VaultState> {
    switch (newState) {
      case VAULT_STATE.NOT_INITIALIZED:
        // Only option is to come from INITIALIZED
        delete this.serverUrl
        delete this.wellKnownCvsConfiguration
        this.state = new Promise((resolve, reject) => {
          resolve(VAULT_STATE.NOT_INITIALIZED)
        })
        break

      case VAULT_STATE.INITIALIZED:
        if (currentState === VAULT_STATE.NOT_INITIALIZED) {
          this.wellKnownCvsConfiguration = await this.request.get<OpenApiComponents.Schemas.CvsConfiguration>(this.serverUrl as string + '/.well-known/cvs-configuration', { responseStatus: 200 }).catch(err => {
            throw new VaultError('not-initialized', err)
          })
        } else { // this.state === VAULT_STATE.LOGGED_IN
          await this.request?.stop()

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

          const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

          const data = await this.request.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
            cvsConf.vault_configuration.v2.token_endpoint,
            reqBody,
            { responseStatus: 200 }
          )

          this.token = data.token

          this.request.defaultUrl = cvsConf.vault_configuration.v2.vault_endpoint

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
          const vaultRequest = this.request
          vaultRequest.waitForOngoingRequestsToFinsh().finally(() => {
            const msg = JSON.parse(e.data) as StorageUpdatedEvent['data']
            if (msg.timestamp !== this.timestamp) {
              this.timestamp = msg.timestamp
              this.emit('storage-updated', this.timestamp)
            }
          }).catch(reason => {})
        })

        this.es.addEventListener('storage-deleted', (e) => {
          const vaultRequest = this.request
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

  async init (serverUrl: string): Promise<string> {
    const url = new URL(serverUrl)
    const serverRootUrl = url.origin
    const serverPrefix = url.pathname.endsWith('/') ? url.pathname.slice(0, -1) : url.pathname
    this.serverUrl = serverRootUrl + serverPrefix

    if (await this.state > VAULT_STATE.INITIALIZED) {
      throw new VaultError('error', new Error('to init the client, it should NOT be INITIALIZED'))
    }
    await this.switchToState(VAULT_STATE.INITIALIZED)
    return this.serverUrl
  }

  async login (username: string, password: string, timestamp?: number): Promise<void> {
    if (await this.state !== VAULT_STATE.INITIALIZED) {
      throw new VaultError('error', new Error('in order to login you should be in state INITIALIZED'))
    }
    await this.switchToState(VAULT_STATE.CONNECTED, {
      username,
      password,
      timestamp
    })
  }

  async logout (): Promise<void> {
    if (await this.state < VAULT_STATE.LOGGED_IN) {
      throw new VaultError('error', new Error('in order to log out you should be in state LOGGED IN or CONNECTED'))
    }
    await this.switchToState(VAULT_STATE.INITIALIZED)
  }

  async close (): Promise<void> {
    await this.switchToState(VAULT_STATE.NOT_INITIALIZED)
  }

  async getRemoteStorageTimestamp (): Promise<number | null> {
    if (await this.state < VAULT_STATE.LOGGED_IN) {
      throw new VaultError('unauthorized', 'you must be logged in')
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    try {
      const data = await this.request.get<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>(
        cvsConf.vault_configuration[apiVersion].timestamp_endpoint,
        {
          responseStatus: 200,
          bearerToken: this.token
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
      const data = await this.request.get<OpenApiPaths.ApiV2Vault.Get.Responses.$200>(
        {
          responseStatus: 200,
          bearerToken: this.token
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
      const newState = stateFromError(await this.state, error)
      await this.switchToState(newState)
      throw VaultError.from(error)
    }
  }

  async updateStorage (storage: VaultStorage, force: boolean = false): Promise<number> {
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

      const data = await this.request.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(requestBody, {
        responseStatus: 201,
        bearerToken: this.token,
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
      await this.request.stop()
      await this.request.delete<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
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

  async getRegistrationUrl (username: string, password: string, did: string, passwordStrengthOptions?: PasswordStrengthOptions): Promise<string> {
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    passwordCheck(password, passwordStrengthOptions)

    const responseData = await this.request.get<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>(
      cvsConf.registration_configuration.public_jwk_endpoint,
      { responseStatus: 200 }
    )
    const publicJwk = responseData.jwk

    const userData = {
      did,
      username,
      authkey: await this.computeAuthKey(username, password)
    }

    const regData = await jweEncrypt(
      Buffer.from(JSON.stringify(userData)),
      publicJwk as JWK,
      'A256GCM'
    )

    return cvsConf.registration_configuration.registration_endpoint.replace('{data}', regData)
  }

  private async computeAuthKey (username: string, password: string): Promise<string> {
    if (await this.state < VAULT_STATE.INITIALIZED) {
      throw new VaultError('not-initialized', undefined)
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const keyManager = new KeyManager(username, password, cvsConf.vault_configuration[apiVersion].key_derivation)
    await keyManager.initialized
    return keyManager.authKey
  }
}
