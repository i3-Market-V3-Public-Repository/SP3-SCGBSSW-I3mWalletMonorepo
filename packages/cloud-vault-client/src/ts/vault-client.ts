import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiComponents, OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import axios, { AxiosError } from 'axios'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import EventSource from 'eventsource'
import { apiVersion } from './config'
import { KeyManager } from './key-manager'
import { SecretKey } from './secret-key'
import type { VaultConnError } from './types/error'
import type { VaultEvent, VaultConflictEvent, VaultConnectedEvent, VaultConnErrorEvent, VaultDisconnectedEvent, VaultLoggedOutEvent, VaultStorageUpdatedEvent } from './types/events'

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
  initialized: Promise<boolean>

  private es?: EventSource

  constructor (serverUrl: string, username: string, password: string, name?: string) {
    super({ captureRejections: true })

    this.name = name ?? randomBytes(16).toString('hex')
    this.serverUrl = serverUrl

    this.username = username
    this.password = password

    this.initialized = this.init()
  }

  emit (eventName: VaultEvent['name'], ...args: VaultEvent['args']): boolean
  emit (eventName: string | symbol, ...args: any[]): boolean {
    return super.emit(eventName, ...args)
  }

  private async init (): Promise<boolean> {
    try {
      await this.getWellKnownCvsConfiguration()
    } catch (error) {
      this.emitError(error)
      return false
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    this.keyManager = new KeyManager(this.username, this.password as string, cvsConf.vault_configuration[apiVersion].key_derivation)
    try {
      await this.keyManager.initialized
    } catch (error) {
      this.emitError(error)
      return false
    }
    delete this.password // we don't need to store the password anymore if the keys are already derived
    return true
  }

  private emitError (error: any): void {
    if (error instanceof AxiosError) {
      if ((error.response?.data as OpenApiComponents.Schemas.ApiError).name === 'Unauthorized') {
        this.logout()
        this.emit('logged-out')
      } else {
        const vaultConnError: VaultConnError = {
          request: {
            method: error.config?.method?.toLocaleUpperCase(),
            url: error.config?.url,
            headers: error.config?.headers,
            data: error.config?.data
          },
          response: {
            status: error.response?.status,
            headers: error.response?.headers as { [key: string]: string },
            data: error.response?.data
          }
        }
        this.emit(this.defaultEvents.error, vaultConnError)
      }
    } else {
      this.emit(this.defaultEvents.error, error)
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
      throw new Error('Cannot subscribe to events without login first')
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
      this.emit(this.defaultEvents.connected, msg.timestamp)
    })

    this.es.addEventListener('storage-updated', (e) => {
      const msg = JSON.parse(e.data) as StorageUpdatedEvent['data']
      if (msg.timestamp !== this.timestamp) {
        this.timestamp = msg.timestamp
        this.emit(this.defaultEvents['storage-updated'], this.timestamp)
      }
    })

    this.es.addEventListener('storage-deleted', (e) => {
      delete this.timestamp
      this.close()
      this.emit(this.defaultEvents['storage-deleted'])
    })

    this.es.onerror = (e) => {
      this.emitError(e)
    }
  }

  close (): void {
    this.logout()
    this.emit(this.defaultEvents.close)
  }

  async getAuthKey (): Promise<string | null> {
    const initialized = await this.initialized
    if (!initialized) { // try again to initialize
      try {
        await this.init()
      } catch (error) {
        this.emitError(error)
        return null
      }
    }
    return (this.keyManager as KeyManager).authKey
  }

  async login (): Promise<boolean> {
    const initialized = await this.initialized
    if (!initialized) { // try again to initialize
      try {
        await this.init()
      } catch (error) {
        this.emitError(error)
        return false
      }
    }
    const reqBody: OpenApiPaths.ApiV2VaultToken.Post.RequestBody = {
      username: this.username,
      authkey: (this.keyManager as KeyManager).authKey
    }
    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
        this.serverUrl + cvsConf.vault_configuration.v2.token_endpoint, reqBody
      )

      if (res.status !== 200) {
        this.emitError(res)
        return false
      }

      const body = res.data
      this.token = body.token

      await this.initEventSourceClient()
      return true
    } catch (error) {
      this.emitError(error)
      return false
    }
  }

  logout (): void {
    this.token = undefined
    this.es?.close()
  }

  async getRemoteStorageTimestamp (): Promise<number | null> {
    try {
      if (this.token === undefined) {
        this.emit(this.defaultEvents['login-required'])
        return null
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
      )
      if (res.status !== 200) {
        this.emitError(res)
        return null
      }
      if ((this.timestamp ?? 0) < res.data.timestamp) {
        this.timestamp = res.data.timestamp
      }
      return res.data.timestamp
    } catch (error) {
      this.emitError(error)
      return null
    }
  }

  async getStorage (): Promise<VaultStorage | null> {
    try {
      if (this.token === undefined) {
        this.emit(this.defaultEvents['login-required'])
        return null
      }
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
        this.emitError(res)
        return null
      }

      if (res.data.timestamp < (this.timestamp ?? 0)) {
        this.emitError(new Error('Received timestamp is older than the latest one published'))
        return null
      }
      const storage = key.decrypt(Buffer.from(res.data.ciphertext, 'base64url'))
      this.timestamp = res.data.timestamp

      return {
        storage,
        timestamp: res.data.timestamp
      }
    } catch (error) {
      this.emitError(error)
      return null
    }
  }

  async updateStorage (storage: VaultStorage, force: boolean = false): Promise<boolean> {
    try {
      if (this.token === undefined) {
        this.emit(this.defaultEvents['login-required'])
        return false
      }
      if (this.timestamp !== undefined && (storage.timestamp ?? 0) < this.timestamp) {
        this.emit(this.defaultEvents.conflict)
        return false
      }
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
        this.emitError(res)
        return false
      }
      this.timestamp = res.data.timestamp
      return true
    } catch (error) {
      this.emitError(error)
    }
    return false
  }

  async deleteStorage (): Promise<boolean> {
    try {
      if (this.token === undefined) {
        this.logout()
        this.emit(this.defaultEvents['login-required'])
        return false
      }
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
        this.emitError(res)
        return false
      }
      this.emit(this.defaultEvents['storage-deleted'])
      delete this.timestamp
      this.close()
      return true
    } catch (error) {
      this.emitError(error)
    }
    return false
  }

  async getServerPublicKey (): Promise<OpenApiComponents.Schemas.JwkEcPublicKey | null> {
    try {
      await this.getWellKnownCvsConfiguration()
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.get<OpenApiPaths.ApiV2RegistrationPublicJwk.Get.Responses.$200>(
        this.serverUrl + cvsConf.registration_configuration.public_jwk_endpoint
      )
      if (res.status !== 200) {
        this.emitError(res)
        return null
      }
      return res.data.jwk
    } catch (error) {
      this.emitError(error)
      return null
    }
  }
}
