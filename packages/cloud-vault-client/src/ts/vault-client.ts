import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import axios from 'axios'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import EventSource from 'eventsource'
import { apiVersion } from './config'
import { VaultError } from './error'
import { KeyManager } from './key-manager'
import { SecretKey } from './secret-key'

import type { ArgsForEvent, VaultEventName } from './events'

type CbOnEventFn<T extends VaultEventName> = (...args: ArgsForEvent<T>) => void

export interface VaultStorage {
  storage: Buffer
  timestamp?: number // milliseconds elapsed since epoch of the last downloaded storage
}

export class VaultClient extends EventEmitter {
  timestamp?: number
  private token?: string
  name: string
  serverUrl: string
  username: string
  private password?: string // it will be only stored until keys are properly derived from it
  private keyManager?: KeyManager
  wellKnownCvsConfiguration?: OpenApiComponents.Schemas.CvsConfiguration
  private readonly initialized: Promise<void>

  private es?: EventSource

  constructor (serverUrl: string, username: string, password: string, name?: string) {
    super({ captureRejections: true })

    this.name = name ?? randomBytes(16).toString('hex')
    this.serverUrl = serverUrl

    this.username = username
    this.password = password

    this.initialized = this.init()
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
    try {
      await this.getWellKnownCvsConfiguration()
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

      this.keyManager = new KeyManager(this.username, this.password as string, cvsConf.vault_configuration[apiVersion].key_derivation)
      await this.keyManager.initialized

      delete this.password // we don't need to store the password anymore if the keys are already derived
    } catch (error) {
      throw VaultError.from(error)
    }
  }

  private async getWellKnownCvsConfiguration (): Promise<void> {
    const res = await axios.get<OpenApiPaths.WellKnownCvsConfiguration.Get.Responses.$200>(
      this.serverUrl + '/.well-known/cvs-configuration'
    )
    this.wellKnownCvsConfiguration = res.data
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

    this.es.onmessage = (msg) => {
      console.log(msg)
    }
    this.es.addEventListener('connected', (e) => {
      const msg = JSON.parse(e.data) as ConnectedEvent['data']
      this.timestamp = msg.timestamp
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
      this.emitError(e)
    }
  }

  private emitError (error: unknown): void {
    const vaultError = VaultError.from(error)
    switch (vaultError.message) {
      case 'unauthorized':
        this.logout()
        this.emit('logged-out')
        break
      case 'sse-connection-error':
        this.emit('connection-error', vaultError)
        break
      default:
        this.emit('error', vaultError)
        break
    }
  }

  logout (): void {
    this.es?.close()
    this.token = undefined
    this.emit('logged-out')
  }

  async getAuthKey (): Promise<string> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    return (this.keyManager as KeyManager).authKey
  }

  async login (): Promise<void> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    const reqBody: OpenApiPaths.ApiV2VaultToken.Post.RequestBody = {
      username: this.username,
      authkey: (this.keyManager as KeyManager).authKey
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const res = await axios.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
      this.serverUrl + cvsConf.vault_configuration.v2.token_endpoint, reqBody
    ).catch((error) => { throw VaultError.from(error) })

    if (res.status !== 200) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (200)`
      }, { cause: 'HTTP status does not match the expected one' })
    }

    const body = res.data
    this.token = body.token

    await this.initEventSourceClient().catch((error) => { throw VaultError.from(error) })
  }

  async getRemoteStorageTimestamp (): Promise<number | null> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
    const res = await axios.get<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>(
      this.serverUrl + cvsConf.vault_configuration[apiVersion].timestamp_endpoint,
      {
        headers: {
          Authorization: 'Bearer ' + this.token,
          'Content-Type': 'application/json'
        }
      }
    ).catch((error) => { throw VaultError.from(error) })

    if (res.status !== 200) {
      throw new VaultError('validation', {
        description: `Received HTTP status ${res.status} does not match the expected one (200)`
      }, { cause: 'HTTP status does not match the expected one' })
    }

    if ((this.timestamp ?? 0) < res.data.timestamp) {
      this.timestamp = res.data.timestamp
    }

    return res.data.timestamp
  }

  async getStorage (): Promise<VaultStorage> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const key: SecretKey = (this.keyManager as KeyManager).encKey

      const res = await axios.get<OpenApiPaths.ApiV2Vault.Get.Responses.$200>(
        this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
        {
          headers: {
            Authorization: 'Bearer ' + this.token,
            'Content-Type': 'application/json'
          }
        })
      if (res.status !== 200) {
        throw new VaultError('validation', {
          description: `Received HTTP status ${res.status} does not match the expected one (200)`
        }, { cause: 'HTTP status does not match the expected one' })
      }

      if (res.data.timestamp < (this.timestamp ?? 0)) {
        throw new VaultError('validation', {
          description: 'WEIRD!!! Received timestamp is older than the one received in previous events'
        })
      }

      const storage = key.decrypt(Buffer.from(res.data.ciphertext, 'base64url'))
      this.timestamp = res.data.timestamp

      return {
        storage,
        timestamp: res.data.timestamp
      }
    } catch (error) {
      throw VaultError.from(error)
    }
  }

  async updateStorage (storage: VaultStorage, force: boolean = false): Promise<void> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    if (this.timestamp !== undefined && (storage.timestamp ?? 0) < this.timestamp) {
      throw new VaultError('conflict', {
        localTimestamp: storage.timestamp,
        remoteTimestamp: this.timestamp
      })
    }

    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const key: SecretKey = (this.keyManager as KeyManager).encKey

      if (force) {
        const remoteTimestamp = await this.getRemoteStorageTimestamp()
        storage.timestamp = (remoteTimestamp !== null) ? remoteTimestamp : undefined
      }

      const encryptedStorage = key.encrypt(storage.storage)

      const requestBody: OpenApiPaths.ApiV2Vault.Post.RequestBody = {
        ciphertext: encryptedStorage.toString('base64url'),
        timestamp: storage.timestamp
      }
      const res = await axios.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(
        this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
        requestBody,
        {
          headers: {
            Authorization: 'Bearer ' + this.token,
            'Content-Type': 'application/json'
          }
        })
      if (res.status !== 201) {
        throw new VaultError('validation', {
          description: `Received HTTP status ${res.status} does not match the expected one (201)`
        }, { cause: 'HTTP status does not match the expected one' })
      }
      this.timestamp = res.data.timestamp
    } catch (error) {
      throw VaultError.from(error)
    }
  }

  async deleteStorage (): Promise<void> {
    await this.initialized.catch((error) => { throw new VaultError('not-initialized', error) })

    if (this.token === undefined) {
      throw new VaultError('unauthorized', undefined)
    }

    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.delete<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
        this.serverUrl + cvsConf.vault_configuration[apiVersion].vault_endpoint,
        {
          headers: {
            Authorization: 'Bearer ' + this.token
          }
        }
      )
      if (res.status !== 204) {
        throw new VaultError('validation', {
          description: `Received HTTP status ${res.status} does not match the expected one (204)`
        }, { cause: 'HTTP status does not match the expected one' })
      }

      delete this.timestamp
      this.logout()
    } catch (error) {
      throw VaultError.from(error)
    }
  }

  async getServerPublicKey (): Promise<OpenApiComponents.Schemas.JwkEcPublicKey> {
    try {
      await this.getWellKnownCvsConfiguration()
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.get<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>(
        this.serverUrl + cvsConf.registration_configuration.public_jwk_endpoint
      )
      if (res.status !== 200) {
        throw new VaultError('validation', {
          description: `Received HTTP status ${res.status} does not match the expected one (200)`
        }, { cause: 'HTTP status does not match the expected one' })
      }
      return res.data.jwk
    } catch (error) {
      throw VaultError.from(error)
    }
  }
}
