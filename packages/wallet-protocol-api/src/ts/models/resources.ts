import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor, Params } from '../types'

export class ResourcesApi {
  constructor (protected api: ApiExecutor) { }

  async list (options?: WalletPaths.ResourceList.QueryParameters): Promise<WalletPaths.ResourceList.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/resources',
      method: 'GET'
    }, undefined, options as Params, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.ResourceList.Responses.$200
  }

  async create (body: WalletPaths.ResourceCreate.RequestBody): Promise<WalletPaths.ResourceCreate.Responses.$201> {
    const response = await this.api.executeQuery({
      path: '/resources',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, undefined, undefined, body)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.ResourceCreate.Responses.$201
  }
}
