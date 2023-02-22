import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import request from './request'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import EventSource from 'eventsource'
import { apiVersion } from './config'
import { VaultError } from './error'
import { KeyManager } from './key-manager'

import type { ArgsForEvent, VaultEventName } from './events'

type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void

export interface VaultStorage {
  storage: Buffer
  timestamp?: number // milliseconds elapsed since epoch of the last downloaded storage
}

export const VAULT_CONNECTED = 1 as const
export const VAULT_DISCONNECTED = 0 as const

export class VaultClient extends EventEmitter {
  timestamp?: number
  token?: string
  name: string
  serverUrl: string
  wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration
  status: typeof VAULT_CONNECTED | typeof VAULT_DISCONNECTED

  private _initialized: Promise<void>
  private keyManager?: KeyManager

  private es?: EventSource

  constructor (serverUrl: string, name?: string) {
    super({ captureRejections: true })

    this.name = name ?? randomBytes(16).toString('hex')
    this.serverUrl = serverUrl

    this.status = VAULT_DISCONNECTED

    this._initialized = this.init()
  }

  get initialized (): Promise<void> {
    return new Promise((resolve, reject) => {
      this._initialized.then(() => {
        resolve()
      }).catch(() => {
        this._initialized = this.init().then(() => {
          resolve()
        }).catch((reason) => {
          reject(reason)
        })
      })
    })
  }

  emit<T extends VaultEventName>(eventName: T, ...args: ArgsForEvent<T>): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean {
    return super.emit(eventName, ...args)
  }

  on<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this
  on (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.on(eventName, listener)
  }

  once<T extends VaultEventName>(event: T, cb: CbOnEventFn<T>): this
  once (eventName: string | symbol, listener: (...args: any[]) => void): this
  once (eventName: string | symbol, listener: (...args: any[]) => void): this {
    return super.once(eventName, listener)
  }

  private async init (): Promise<void> {
    this.wellKnownCvsConfiguration = await VaultClient.getWellKnownCvsConfiguration(this.serverUrl).catch(err => {
      throw new VaultError('not-initialized', err)
    })
    if (this.token !== undefined) {
      await this.initEventSourceClient().catch((error) => { throw VaultError.from(error) })
    }
  }

  private async initEventSourceClient (): Promise<void> {
    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    this.es = new EventSource(this.serverUrl + cvsConf.vault_configuration[apiVersion].events_endpoint, {
      headers: {
        Authorization: 'Bearer ' + this.token
      }
    })

    this.es.addEventListener('connected', (e) => {
      const msg = JSON.parse(e.data) as ConnectedEvent['data']
      this.timestamp = msg.timestamp
      this.status = VAULT_CONNECTED
      this.emit('connected', msg.timestamp)
    })

    this.es.addEventListener('storage-updated', (e) => {
      const msg = JSON.parse(e.data) as StorageUpdatedEvent['data']
      if (msg.timestamp !== this.timestamp) {
        this.timestamp = msg.timestamp
        this.emit('storage-updated', this.timestamp)
      }
    })

    this.es.addEventListener('storage-deleted', (e) => {
      delete this.timestamp
      this.logout()
      this.emit('storage-deleted')
    })

    this.es.onerror = (e) => {
      if (this.status === VAULT_CONNECTED) {
        this.status = VAULT_DISCONNECTED
        this.emit('disconnected')
      }
    }
  }

  private async initKeyManager (username: string, password: string): Promise<void> {
    await this.initialized

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    this.keyManager = new KeyManager(username, password, cvsConf.vault_configuration[apiVersion].key_derivation)
    await this.keyManager.initialized
  }

  logout (): void {
    this.es?.close()
    this.token = undefined
    this.emit('disconnected')
    this.emit('unauthorized')
  }

  async login (username: string, password: string, token?: string): Promise<void> {
    await this.initialized
    await this.initKeyManager(username, password)

    if (token === undefined) {
      const reqBody: OpenApiPaths.ApiV2VaultToken.Post.RequestBody = {
        username,
        authkey: (this.keyManager as KeyManager).authKey
      }
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const data = await request.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
        this.serverUrl + cvsConf.vault_configuration.v2.token_endpoint, reqBody,
        { responseStatus: 200 }
      )

      this.token = data.token
    } else {
      this.token = token
    }

    await this.initEventSourceClient().catch((error) => { throw VaultError.from(error) })
  }

  async getRemoteStorageTimestamp (): Promise<number | null> {
    await this.initialized

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const data = await request.get<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>(
      this.serverUrl + cvsConf.vault_configuration[apiVersion].timestamp_endpoint,
      {
        bearerToken: this.token,
        responseStatus: 200
      }
    )

    if ((this.timestamp ?? 0) < data.timestamp) {
      this.timestamp = data.timestamp
    }

    return data.timestamp
  }

  async getStorage (): Promise<VaultStorage> {
    await this.initialized

    if (this.token === undefined || this.keyManager === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

      const data = await request.get<OpenApiPaths.ApiV2Vault.Get.Responses.$200>(
        this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
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

      const storage = this.keyManager.encKey.decrypt(Buffer.from(data.ciphertext, 'base64url'))
      this.timestamp = data.timestamp

      return {
        storage,
        timestamp: data.timestamp
      }
    } catch (error) {
      throw VaultError.from(error)
    }
  }

  async updateStorage (storage: VaultStorage, force: boolean = false): Promise<number> {
    await this.initialized

    if (this.token === undefined || this.keyManager === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    if (this.timestamp !== undefined && (storage.timestamp ?? 0) < this.timestamp) {
      throw new VaultError('conflict', {
        localTimestamp: storage.timestamp,
        remoteTimestamp: this.timestamp
      })
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    if (force) {
      const remoteTimestamp = await this.getRemoteStorageTimestamp()
      storage.timestamp = (remoteTimestamp !== null) ? remoteTimestamp : undefined
    }

    const encryptedStorage = this.keyManager.encKey.encrypt(storage.storage)

    const requestBody: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
      ciphertext: encryptedStorage.toString('base64url'),
      timestamp: storage.timestamp
    }
    const data = await request.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(
      this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
      requestBody,
      {
        bearerToken: this.token,
        responseStatus: 201
      }
    )
    this.timestamp = data.timestamp
    return this.timestamp
  }

  async deleteStorage (): Promise<void> {
    await this.initialized

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    await request.delete<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
      this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
      {
        bearerToken: this.token,
        responseStatus: 204
      }
    )
    delete this.timestamp
    this.logout()
  }

  async getServerPublicKey (): Promise<OpenApiComponents.Schemas.JwkEcPublicKey> {
    await this.initialized
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const data = await request.get<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>(
      this.serverUrl + cvsConf.registration_configuration.public_jwk_endpoint,
      { responseStatus: 200 }
    )
    return data.jwk
  }

  static async getWellKnownCvsConfiguration (serverUrl: string): Promise<OpenApiComponents.Schemas.CvsConfiguration> {
    return await request.get<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>(
      serverUrl + '/.well-known/cvs-configuration',
      { responseStatus: 200 }
    )
  }

  static async computeAuthKey (serverUrl: string, username: string, password: string): Promise<string> {
    const cvsConf = await VaultClient.getWellKnownCvsConfiguration(serverUrl)
    const keyManager = new KeyManager(username, password, cvsConf.vault_configuration[apiVersion].key_derivation)
    await keyManager.initialized
    return keyManager.authKey
  }
}
