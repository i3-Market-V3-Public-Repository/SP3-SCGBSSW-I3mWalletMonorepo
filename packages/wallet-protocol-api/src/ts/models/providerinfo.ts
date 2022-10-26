import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class ProviderInfoApi {
  constructor (protected api: ApiExecutor) { }

  async get (): Promise<WalletPaths.ProviderinfoGet.Responses.$200> {
    return await this.api.executeQuery({
      path: '/providerinfo',
      method: 'GET'
    }, undefined, undefined, undefined)
  }
}
