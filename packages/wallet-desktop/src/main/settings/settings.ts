import { Store } from '@i3m/base-wallet'
import { exportJWK, generateSecret } from 'jose'

import { DEFAULT_WALLET_PACKAGES, Provider, PublicSettings } from '@wallet/lib'
import { Locals, StoreOptions } from '@wallet/main/internal'
import _ from 'lodash'

export type PublicSettingsStore = Store<PublicSettings>
export type PublicSettingsOptions = Partial<StoreOptions<PublicSettings>>

// ** PUBLIC SETTINGS **

export async function fixPublicSettings (locals: Locals): Promise<void> {
  const publicSettings = locals.storeManager.getStore('public-settings')
  const publicSettingsValues = await publicSettings.getStore()

  // Clean public settings
  await publicSettings.clear()
  await publicSettings.set(
    _<PublicSettings>(publicSettingsValues)
      .pick('version', 'auth', 'enc', 'store', 'cloud')
      .omitBy(_.isUndefined)
      .value()
  )
}

// ** PRIVATE SETTINGS **

function validProviders (providers: Provider[]): boolean {
  if (providers === undefined || providers.length === 0) {
    return false
  }

  // Creates an object which parameters say if all providers have this field set
  const filledArguments = providers.reduce((prev, curr) => ({
    name: prev.name || curr.name === undefined,
    provider: prev.provider || curr.provider === undefined,
    network: prev.network || curr.network === undefined,
    rpcUrl: prev.rpcUrl || curr.rpcUrl === undefined
  }), { name: false, provider: false, network: false, rpcUrl: false })

  return Object.values(filledArguments).reduce((prev, curr) => prev && !curr, true)
}

export const fixPrivateSettings = async (locals: Locals): Promise<void> => {
  const { storeManager } = locals
  const settings = storeManager.getStore('private-settings')

  await fixPublicSettings(locals)
  const providers = await settings.get('providers')

  // Setup default providers
  if (!validProviders(providers)) {
    await settings.set('providers', [
      { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' },
      { name: 'Rinkeby', provider: 'did:ethr:rinkeby', network: 'rinkeby', rpcUrl: 'https://rpc.ankr.com/eth_rinkeby' }
    ])
  }

  const wallet = await settings.get('wallet')
  wallet.packages = DEFAULT_WALLET_PACKAGES
  await settings.set('wallet', wallet)

  const secret = await settings.get('secret')
  if (secret === undefined) {
    const key = await generateSecret('HS256', { extractable: true })
    const jwk = await exportJWK(key)
    await settings.set('secret', jwk)
  }
}
