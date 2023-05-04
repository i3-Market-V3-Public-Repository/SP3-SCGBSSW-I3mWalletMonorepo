import { Store } from '@i3m/base-wallet'
import { exportJWK, generateSecret } from 'jose'

import { DEFAULT_WALLET_PACKAGES, Provider, PublicSettings, PUBLIC_SETTINGS_FIELDS } from '@wallet/lib'
import { Locals, StoreOptions } from '@wallet/main/internal'
import _ from 'lodash'

export type PublicSettingsStore = Store<PublicSettings>
export type PublicSettingsOptions = Partial<StoreOptions<PublicSettings>>

// ** PUBLIC SETTINGS **

export async function fixPublicSettings (locals: Locals): Promise<void> {
  const { sharedMemoryManager: shm } = locals

  // Clean public settings
  const cleanPublicSettings = _<PublicSettings>(shm.memory.settings.public)
    .pick(...PUBLIC_SETTINGS_FIELDS)
    .omitBy(_.isUndefined)
    .value() as PublicSettings

  shm.update((mem) => ({
    ...mem,
    settings: {
      ...mem.settings,
      public: cleanPublicSettings
    }
  }))
}

// ** PRIVATE SETTINGS **

function validProviders (providers: Provider[]): boolean {
  if (providers === undefined || providers.length === 0) {
    return false
  }

  // Creates an object which parameters say if all providers have this field set
  const filledArguments = providers.reduce((prev, curr) => ({
    name: prev.name || curr.name === undefined,
    network: prev.network || curr.network === undefined,
    rpcUrl: prev.rpcUrl || !(curr.rpcUrl instanceof Array) || curr.rpcUrl === undefined
  }), { name: false, network: false, rpcUrl: false })

  return Object.values(filledArguments).reduce((prev, curr) => prev && !curr, true)
}

export const fixPrivateSettings = async (locals: Locals): Promise<void> => {
  const { sharedMemoryManager: shm } = locals

  await fixPublicSettings(locals)

  const privateSettings = shm.memory.settings.private

  let providers = privateSettings.providers
  if (!validProviders(providers)) {
    providers = []
  }

  const wallet = privateSettings.wallet
  wallet.packages = DEFAULT_WALLET_PACKAGES

  let secret = privateSettings.secret
  if (secret === undefined) {
    const key = await generateSecret('HS256', { extractable: true })
    secret = await exportJWK(key)
  }

  // Setup default providers
  shm.update((mem) => {
    return {
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          providers,
          wallet,
          secret
        }
      }
    }
  })
}
