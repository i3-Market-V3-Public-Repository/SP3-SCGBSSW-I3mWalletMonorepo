import { WalletComponents, WalletPaths } from '@i3m/wallet-desktop-openapi/types'

import { ApiExecutor, Params } from '../types'

export class IdentitiesApi {
  constructor (protected api: ApiExecutor) { }

  async list (queryParams?: WalletPaths.IdentityList.QueryParameters): Promise<WalletPaths.IdentityList.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/identities',
      method: 'GET'
    }, undefined, queryParams as Params, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentityList.Responses.$200
  }

  async select (queryParams?: WalletPaths.IdentitySelect.QueryParameters): Promise<WalletPaths.IdentitySelect.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/identities/select',
      method: 'GET'
    }, undefined, queryParams as Params, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentitySelect.Responses.$200
  }

  async create (body: WalletPaths.IdentityCreate.RequestBody): Promise<WalletPaths.IdentityCreate.Responses.$201> {
    const response = await this.api.executeQuery({
      path: '/identities',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, undefined, undefined, body)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentityCreate.Responses.$201
  }

  async sign (pathParams: WalletPaths.IdentitySign.PathParameters, body: WalletPaths.IdentitySign.RequestBody): Promise<WalletPaths.IdentitySign.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/identities/{did}/sign',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, pathParams as any, undefined, body)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentitySign.Responses.$200
  }

  async info (pathParams: WalletPaths.IdentityInfo.PathParameters): Promise<WalletPaths.IdentityInfo.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/identities/{did}/info',
      method: 'GET'
    }, pathParams as any, undefined, undefined)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentityInfo.Responses.$200
  }

  async deployTransaction (pathParams: WalletPaths.IdentityDeployTransaction.PathParameters, body: WalletPaths.IdentityDeployTransaction.RequestBody): Promise<WalletPaths.IdentityDeployTransaction.Responses.$200> {
    const response = await this.api.executeQuery({
      path: '/identities/{did}/deploy-tx',
      method: 'POST'
    }, pathParams as any, undefined, body)
    if ((response as WalletComponents.Schemas.ApiError).code !== undefined) {
      throw new Error(`${(response as WalletComponents.Schemas.ApiError).code}: ${(response as WalletComponents.Schemas.ApiError).message}`)
    }
    return response as WalletPaths.IdentityDeployTransaction.Responses.$200
  }
}
