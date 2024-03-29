import * as React from 'react'
import _ from 'lodash'
import { v4 as uuid } from 'uuid'

import { PrivateSettings, Provider, showToastAction } from '@wallet/lib'
import { ActionDispatcher, useSharedMemory } from '@wallet/renderer/communication'

import { ArraySettingsMetadata, MetadataRecord, ObjectSettingsMetadata } from '../settings-metadata'
import { JsonUi } from '@wallet/renderer/components'

const defaultProvider = (): Provider => {
  const id = uuid()
  return { name: id, network: id, rpcUrl: ['http://localhost:8545'] }
}

const validProvider = (provider: Provider, oldProvider: Provider, settings: PrivateSettings, oldSettings: PrivateSettings, dispatch: ActionDispatcher): boolean => {
  // If there are multiple providers with the same provider you can delete one of them

  const providersWithSameProvider = oldSettings.providers
    .reduce((count, p) => p.network === oldProvider.network ? count + 1 : count, 0)

  if (providersWithSameProvider <= 1) {
    // You cannot delete providers that are already used in the wallet
    const requiredProviders = Object
      .entries(settings.wallet.wallets)
      .reduce((dict: any, [key, walletInfo]) => {
        const provider = walletInfo.args.provider as string
        dict[provider] = true
        return dict
      }, {})

    if (Object.keys(requiredProviders).includes(oldProvider.network)) {
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
  label: 'Networks',
  type: 'array',
  key: 'private.providers',
  canDelete: (i, provider, sharedMemory, dispatch) => {
    return validProvider(provider, provider, sharedMemory.settings.private, sharedMemory.settings.private, dispatch)
  },
  defaults: (parent, value) => defaultProvider(),
  innerType: (i, parent) => {
    const providerMetadata: ObjectSettingsMetadata<Provider> = {
      label: (key, provider) => provider.name,
      type: 'object',
      key: `${parent.key}.${i}`,
      canUpdate: (key, value, metadata, sharedMemory, dispatch) => {
        const settings = _.cloneDeep(sharedMemory.settings)
        _.set(settings, key, value)
        const newProvider = _.get(settings, metadata.key)
        const oldProvider = _.get(sharedMemory.settings, metadata.key)

        console.log(value, key)
        console.log(newProvider, oldProvider)
        return validProvider(newProvider, oldProvider, settings.private, sharedMemory.settings.private, dispatch)
      },
      innerType: {
        name: {
          label: 'Name',
          type: 'input',
          key: `${parent.key}.${i}.name`
        },
        rpcUrl: {
          label: 'RPC URL',
          type: 'array',
          innerType: (i, parent) => ({
            label: 'RPC URL',
            type: 'input',
            key: `${parent.key}.${i}`
          }),
          defaults: () => 'http://localhost:8545',
          key: `${parent.key}.${i}.rpcUrl`
        },
        network: {
          label: 'Network',
          type: 'input',
          key: `${parent.key}.${i}.network`
        }
      }
    }
    return providerMetadata
  }
}

function DefaultProviders (): JSX.Element {
  const [shm] = useSharedMemory()

  return (
    <>
      {Object.entries(shm.defaultProviders).map(([id, provider]) => (
        <JsonUi key={id} prop={id} value={provider} defaultActiveKey={[]} />
      ))}
    </>
  )
}

export const walletMetadata: MetadataRecord = {
  Wallet: [
    {
      type: 'info',
      description: {
        title: 'Default providers',
        message: <DefaultProviders />
      }
    },
    providersMetadata
  ]
}
