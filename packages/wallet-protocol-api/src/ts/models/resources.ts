import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class ResourcesApi {
  constructor (protected api: ApiExecutor) { }

  async list (): Promise<WalletPaths.ResourceList.Responses.$200> {
    return await this.api.executeQuery({
      path: '/resources',
      method: 'GET'
    }, undefined, undefined, undefined)
  }

  async create (body: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201> {
    return await this.api.executeQuery({
      path: '/resources',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, undefined, undefined, body)
  }
}
