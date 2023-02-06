import type { ConnectedEvent, StorageUpdatedEvent } from '@i3m/cloud-vault-server'
import type { OpenApiPaths, OpenApiComponents } from '@i3m/cloud-vault-server/types/openapi'
import axios, { AxiosError } from 'axios'
import EventSource from 'eventsource'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { apiVersion } from './config'
import { KeyManager } from './key-manager'

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
    super()

    this.name = name ?? randomBytes(16).toString('hex')
    this.serverUrl = serverUrl

    this.username = username
    this.password = password

    this.initialized = this.init()
  }

  private async init (): Promise<boolean> {
    try {
      await this.getWellKnownCvsConfiguration()
    } catch (error) {
      this.emitError(error)
      return false
    }
    const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

    this.keyManager = new KeyManager(this.username, this.password as string, cvsConf['vault-configuration'][apiVersion]['key-derivation'])
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
    if (error instanceof AxiosError && error.response !== undefined) {
      if ((error.response.data as OpenApiComponents.Schemas.ApiError).name === 'Unauthorized') {
        this.logout()
        this.emit('login-required')
      } else {
        this.emit('error', error.response)
      }
    } else {
      this.emit('error', error)
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

    this.es = new EventSource(this.serverUrl + cvsConf['vault-configuration'][apiVersion].events_endpoint, {
      headers: {
        Authorization: 'Bearer ' + this.token
      }
    })

    this.es.onmessage = (msg) => {
      console.log(msg)
    }
    this.es.addEventListener('connected', (e) => {
      const msg = JSON.parse(e.data) as ConnectedEvent['data']
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
      this.emit('storage-updated')
    })

    this.es.onerror = (e) => {
      this.emit('error', e)
    }
  }

  close (): void {
    this.logout()
    this.emit('close')
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
    return await (this.keyManager as KeyManager).getAuthKey()
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
      authkey: await (this.keyManager as KeyManager).getAuthKey()
    }
    try {
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.post<OpenApiPaths.ApiV2VaultToken.Post.Responses.$200>(
        this.serverUrl + cvsConf['vault-configuration'].v2.token_endpoint, reqBody
      )

      if (res.status !== 200) {
        this.emitError(res)
        return false
      }

      const body = res.data
      this.token = body.token

      await this.initEventSourceClient()
      this.emit('logged-in')
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
        this.emit('login-required')
        return null
      }
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.get<OpenApiPaths.ApiV2VaultTimestamp.Get.Responses.$200>(
        this.serverUrl + cvsConf['vault-configuration'][apiVersion].timestamp_endpoint,
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
      return res.data.timestamp
    } catch (error) {
      this.emitError(error)
      return null
    }
  }

  async updateStorage (storage: OpenApiPaths.ApiV2Vault.Post.RequestBody, force: boolean = false): Promise<boolean> {
    try {
      if (this.token === undefined) {
        this.emit('login-required')
        return false
      }
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration

      if (force) {
        const timestamp = await this.getRemoteStorageTimestamp()
        storage.timestamp = (timestamp !== null) ? timestamp : undefined
      }

      const res = await axios.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(
        this.serverUrl + cvsConf['vault-configuration'][apiVersion].vault_endpoint,
        storage,
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
        this.emit('login-required')
        return false
      }
      const cvsConf = this.wellKnownCvsConfiguration as OpenApiComponents.Schemas.CvsConfiguration
      const res = await axios.delete<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
        this.serverUrl + cvsConf['vault-configuration'][apiVersion].vault_endpoint,
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
      this.emit('storage-deleted')
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
        this.serverUrl + cvsConf['registration-configuration']['public-jwk_endpoint']
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
