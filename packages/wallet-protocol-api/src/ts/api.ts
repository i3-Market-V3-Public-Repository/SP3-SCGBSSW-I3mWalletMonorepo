import { Session, HttpInitiatorTransport } from '@i3m/wallet-protocol'
import { WalletApiError } from './error'
import { DidJwtApi, DisclosureApi, IdentitiesApi, ProviderInfoApi, ResourcesApi, TransactionApi } from './models'
import { ApiExecutor, Params, Body, ApiMethod } from './types'

export class WalletApi implements ApiExecutor {
  public identities: IdentitiesApi
  public transaction: TransactionApi
  public resources: ResourcesApi
  public disclosure: DisclosureApi
  public didJwt: DidJwtApi
  public providerinfo: ProviderInfoApi

  constructor (protected session: Session<HttpInitiatorTransport>) {
    this.identities = new IdentitiesApi(this)
    this.transaction = new TransactionApi(this)
    this.resources = new ResourcesApi(this)
    this.disclosure = new DisclosureApi(this)
    this.didJwt = new DidJwtApi(this)
    this.providerinfo = new ProviderInfoApi(this)
  }

  public async executeQuery<T>(api: ApiMethod, pathParams: Params, queryParams: Params, bodyObject: Body): Promise<T> {
    let queryParamsString = ''
    if (queryParams !== undefined) {
      queryParamsString = '?' + Object
        .keys(queryParams)
        .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(queryParams[key])}`)
        .join('&')
    }

    let body
    if (bodyObject !== undefined) {
      body = JSON.stringify(bodyObject)
    }

    let url = api.path + queryParamsString
    if (pathParams !== undefined) {
      for (const [key, value] of Object.entries(pathParams)) {
        url = url.replace(`{${key}}`, value)
      }
    }

    const resp = await this.session.send({
      url,
      init: {
        headers: api.headers,
        method: api.method,
        body
      }
    })
    const respBody = JSON.parse(resp.body)
    if (resp.status >= 300 || resp.status < 200) {
      throw new WalletApiError(respBody.reason ?? 'Unknown reason', resp.status, respBody)
    }
    return respBody
  }
}
