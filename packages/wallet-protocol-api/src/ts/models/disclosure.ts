import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor } from '../types'

export class DisclosureApi {
  constructor (protected api: ApiExecutor) { }

  async disclose (pathParams: WalletPaths.SelectiveDisclosure.PathParameters): Promise<WalletPaths.SelectiveDisclosure.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/disclosure/{jwt}',
      method: 'GET'
    }, pathParams as any, undefined, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.SelectiveDisclosure.Responses.$200
  }
}
