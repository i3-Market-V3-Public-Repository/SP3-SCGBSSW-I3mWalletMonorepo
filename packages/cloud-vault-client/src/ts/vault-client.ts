import type { CONNECTED_EVENT, STORAGE_UPDATED_EVENT } from '@i3m/cloud-vault-server'
import type { OpenApiPaths } from '@i3m/cloud-vault-server/types/openapi'
import axios from 'axios'
import EventSource from 'eventsource'
import { randomBytes } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { apiVersion } from './config'

export class VaultClient extends EventEmitter {
  timestamp?: number
  token?: string
  name: string
  serverUrl: string
  vaultPath: string

  private es!: EventSource

  constructor (serverUrl: string, name?: string) {
    super()

    this.name = name ?? randomBytes(16).toString('hex')
    this.serverUrl = serverUrl
    this.vaultPath = `/api/v${apiVersion}/vault`
  }

  private async initEventSourceClient (): Promise<void> {
    if (this.token === undefined) {
      throw new Error('Cannot subscribe to events without login first')
    }
    const vaultUrl = this.serverUrl + this.vaultPath
    const sseEndpoint = vaultUrl + '/events'

    this.es = new EventSource(sseEndpoint, {
      headers: {
        Authorization: 'Bearer ' + this.token
      }
    })

    this.es.addEventListener('connected', (e) => {
      const msg = JSON.parse(e.data) as CONNECTED_EVENT['data']
      this.emit('connected', msg.timestamp)
    })

    this.es.addEventListener('storage-updated', (e) => {
      const msg = JSON.parse(e.data) as STORAGE_UPDATED_EVENT['data']
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

  async login (username: string, authkey: string): Promise<boolean> {
    const reqBody: OpenApiPaths.ApiV2VaultAuth.Post.RequestBody = {
      username,
      authkey
    }
    try {
      const res = await axios.post<OpenApiPaths.ApiV2VaultAuth.Post.Responses.$200>(this.serverUrl + this.vaultPath + '/auth', reqBody)

      if (res.status !== 200) {
        return false
      }

      const body = res.data
      this.token = body.token

      await this.initEventSourceClient()
      this.emit('logged-in')
      return true
    } catch (error) {
      this.emit('error', error)
      return false
    }
  }

  logout (): void {
    this.token = undefined
    this.es.close()
  }

  async updateStorage (storage: OpenApiPaths.ApiV2Vault.Post.RequestBody, force: boolean = false): Promise<boolean> {
    if (this.token === undefined) {
      this.emit('login-required')
      return false
    }
    const res = await axios.post<OpenApiPaths.ApiV2Vault.Post.Responses.$201>(
      this.serverUrl + this.vaultPath,
      storage,
      {
        headers: {
          Authorization: 'Bearer ' + this.token,
          'Content-Type': 'application/json'
        }
      })
    if (res.status !== 201) {
      const error = res.data as unknown as OpenApiPaths.ApiV2Vault.Post.Responses.Default
      if (error.name === 'Unauthorized') {
        this.logout()
        this.emit('login-required')
      } else {
        this.emit('error', res.data)
      }
      return false
    }

    this.timestamp = res.data.timestamp
    return true
  }

  async deleteStorage (): Promise<boolean> {
    if (this.token === undefined) {
      this.logout()
      this.emit('login-required')
      return false
    }
    const res = await axios.get<OpenApiPaths.ApiV2Vault.Delete.Responses.$204>(
      this.serverUrl + this.vaultPath,
      {
        headers: {
          Authorization: 'Bearer ' + this.token
        }
      }
    )
    if (res.status !== 204) {
      const error = res.data as unknown as OpenApiPaths.ApiV2Vault.Post.Responses.Default
      if (error.name === 'Unauthorized') {
        this.logout()
        this.emit('login-required')
      } else {
        this.emit('error', res.data)
      }
      return false
    }

    this.emit('storage-deleted')
    return true
  }
}
