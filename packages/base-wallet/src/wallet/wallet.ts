/* DO NOT MODIFY THIS FILE */
import { WalletPaths } from '@i3-market/wallet-desktop-openapi/types'
import { BaseWalletModel } from '../app'

export interface Wallet {
  /**
   * @throws Error
   */
  wipe: () => Promise<void>

  getResources: () => Promise<BaseWalletModel['resources']>
  getIdentities: () => Promise<BaseWalletModel['identities']>

  // Api methods
  accountList: (queryParameters: WalletPaths.AccountList.QueryParameters) => Promise<WalletPaths.AccountList.Responses.$200>
  accountCreate: (requestBody: WalletPaths.AccountCreate.RequestBody) => Promise<WalletPaths.AccountCreate.Responses.$201>
  accountSign: (requestBody: WalletPaths.AccountSign.RequestBody) => Promise<WalletPaths.AccountSign.Responses.$200>
  accountVerify: (requestBody: WalletPaths.AccountVerify.RequestBody) => Promise<WalletPaths.AccountVerify.Responses.$200>
  accountEncrypt: (requestBody: WalletPaths.AccountEncrypt.RequestBody) => Promise<WalletPaths.AccountEncrypt.Responses.$200>
  accountDecrypt: (requestBody: WalletPaths.AccountDecrypt.RequestBody) => Promise<WalletPaths.AccountDecrypt.Responses.$200>
  identityList: (queryParameters: WalletPaths.IdentityList.QueryParameters) => Promise<WalletPaths.IdentityList.Responses.$200>
  identityCreate: (requestBody: WalletPaths.IdentityCreate.RequestBody) => Promise<WalletPaths.IdentityCreate.Responses.$201>
  identitySelect: (queryParameters: WalletPaths.IdentitySelect.QueryParameters) => Promise<WalletPaths.IdentitySelect.Responses.$200>
  resourceList: () => Promise<WalletPaths.ResourceList.Responses.$200>
  resourceCreate: (requestBody: WalletPaths.ResourceCreate.RequestBody) => Promise<WalletPaths.ResourceCreate.Responses.$201>
  selectiveDisclosure: (pathParameters: WalletPaths.SelectiveDisclosure.PathParameters) => Promise<WalletPaths.SelectiveDisclosure.Responses.$200>
}
