import _ from 'lodash'
import { v4 as uuid } from 'uuid'

import { Provider, SharedMemory, showToastAction } from '@wallet/lib'
import { ActionDispatcher } from '@wallet/renderer/communication'

import { ArraySettingsMetadata, ObjectSettingsMetadata, SettingsMetadataRecord } from '../settings-metadata'

const defaultProvider = { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' }

const validProvider = (provider: Provider, oldProvider: Provider, settings: SharedMemory['settings'], oldSettings: SharedMemory['settings'], dispatch: ActionDispatcher): boolean => {
  // If there are multiple providers with the same provider you can delete one of them
  const providersWithSameProvider = oldSettings.providers
    .reduce((count, p) => p.provider === oldProvider.provider ? count + 1 : count, 0)
  console.log(providersWithSameProvider)
  if (providersWithSameProvider <= 1) {
    // You cannot delete providers that are already used in the wallet
    const requiredProviders = Object
      .entries(settings.wallet.wallets)
      .reduce((dict: any, [key, walletInfo]) => {
        const provider = walletInfo.args.provider as string
        dict[provider] = true
        return dict
      }, {})

    console.log('new', provider, Object.keys(requiredProviders).includes(provider.provider))
    console.log('old', oldProvider, Object.keys(requiredProviders).includes(oldProvider.provider))

    if (Object.keys(requiredProviders).includes(oldProvider.provider)) {
      dispatch(showToastAction.create({
        message: 'Cannot modify provider',
        details: `Provider ${provider.name} cannot be modified because it will lead to orphan wallets.`,
        type: 'warning'
      }))

      return false
    }
  }

  const providersWithSameName = settings.providers
    .reduce((count, p) => p.name === provider.name ? count + 1 : count, 0)
  if (providersWithSameName > 1) {
    dispatch(showToastAction.create({
      message: 'Cannot modify provider',
      details: `Provider ${provider.name} cannot be modified because two providers will have the same name.`,
      type: 'warning'
    }))

    return false
  }

  return true
}

const providersMetadata: ArraySettingsMetadata<Provider> = {
  label: 'Providers',
  type: 'array',
  key: 'providers',
  canDelete: (i, provider, sharedMemory, dispatch) => {
    return validProvider(provider, provider, sharedMemory.settings, sharedMemory.settings, dispatch)
  },
  defaults: (parent, value) => ({
    ...defaultProvider,
    name: uuid()
  }),
  innerType: (i, parent) => {
    const providerMetadata: ObjectSettingsMetadata<Provider> = {
      label: `Provider ${i + 1}`,
      type: 'object',
      key: `${parent.key}.${i}`,
      canUpdate: (key, value, metadata, sharedMemory, dispatch) => {
        const settings = _.cloneDeep(sharedMemory.settings)
        _.set(settings, key, value)
        const newProvider = _.get(settings, metadata.key)
        const oldProvider = _.get(sharedMemory.settings, metadata.key)

        console.log(value, key)
        console.log(newProvider, oldProvider)
        return validProvider(newProvider, oldProvider, settings, sharedMemory.settings, dispatch)
      },
      innerType: {
        name: {
          label: 'Name',
          type: 'input',
          key: `${parent.key}.${i}.name`
        },
        rpcUrl: {
          label: 'RPC URL',
          type: 'input',
          key: `${parent.key}.${i}.rpcUrl`
        },
        network: {
          label: 'Network',
          type: 'input',
          key: `${parent.key}.${i}.network`
        },
        provider: {
          label: 'Provider',
          type: 'input',
          key: `${parent.key}.${i}.provider`
        }
      }
    }
    return providerMetadata
  }
}

export const walletMetadata: SettingsMetadataRecord = {
  Wallet: [
    providersMetadata
  ]
}
