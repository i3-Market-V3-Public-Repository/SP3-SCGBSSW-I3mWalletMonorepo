/* DO NOT MODIFY THIS FILE */
import { WalletPaths } from '@i3m/wallet-desktop-openapi/types'
import { BaseWalletModel } from '../app'
import { WalletFunctionMetadata } from './wallet-metadata'

export interface Wallet {
  call: (functionMetadata: WalletFunctionMetadata) => Promise<void>

  getResources: () => Promise<BaseWalletModel['resources']>
  getIdentities: () => Promise<BaseWalletModel['identities']>

  deleteResource: (id: string) => Promise<void>
  deleteIdentity: (did: string) => Promise<void>

  // Api methods
  identityList: (queryParameters: WalletPaths.IdentityList.QueryParameters) => Promise<WalletPaths.IdentityList.Responses.$200>
  identityCreate: (requestBody: WalletPaths.IdentityCreate.RequestBody) => Promise<WalletPaths.IdentityCreate.Responses.$201>
  identitySelect: (queryParameters: WalletPaths.IdentitySelect.QueryParameters) => Promise<WalletPaths.IdentitySelect.Responses.$200>
  identitySign: (pathParameters: WalletPaths.IdentitySign.PathParameters, requestBody: WalletPaths.IdentitySign.RequestBody) => Promise<WalletPaths.IdentitySign.Responses.$200>
  identityInfo: (pathParameters: WalletPaths.IdentityInfo.PathParameters) => Promise<WalletPaths.IdentityInfo.Responses.$200>
  identityDeployTransaction: (pathParameters: WalletPaths.IdentityDeployTransaction.PathParameters, requestBody: WalletPaths.IdentityDeployTransaction.RequestBody) => Promise<WalletPaths.IdentityDeployTransaction.Responses.$200>
  resourceList: () => Promise<WalletPaths.ResourceList.Responses.$200>
  resourceCreate: (requestBody: WalletPaths.ResourceCreate.RequestBody) => Promise<WalletPaths.ResourceCreate.Responses.$201>
  selectiveDisclosure: (pathParameters: WalletPaths.SelectiveDisclosure.PathParameters) => Promise<WalletPaths.SelectiveDisclosure.Responses.$200>
  transactionDeploy: (requestBody: WalletPaths.TransactionDeploy.RequestBody) => Promise<WalletPaths.TransactionDeploy.Responses.$200>
}
