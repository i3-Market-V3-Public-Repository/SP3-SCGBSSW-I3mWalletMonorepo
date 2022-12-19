import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class ProviderInfoApi {
  constructor (protected api: ApiExecutor) { }

  async get (): Promise<WalletPaths.ProviderinfoGet.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/providerinfo',
      method: 'GET'
    }, undefined, undefined, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.ProviderinfoGet.Responses.$200
  }
}
