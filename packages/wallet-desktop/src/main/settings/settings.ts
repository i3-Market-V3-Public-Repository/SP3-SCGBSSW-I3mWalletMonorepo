import ElectronStore, { Options as ElectronStoreOptions } from 'electron-store'
import { generateSecret, exportJWK } from 'jose'
import _ from 'lodash'

import { PrivateSettings, PublicSettings, createDefaultPrivateSettings, Provider } from '@wallet/lib'
import { Locals, logger } from '@wallet/main/internal'

export type PublicSettingsStore = ElectronStore<PublicSettings>
export type PublicSettingsOptions = ElectronStoreOptions<PublicSettings>

export const initPublicSettings = async (options: PublicSettingsOptions, locals: Locals): Promise<PublicSettingsStore> => {
  const fixedOptions = _.merge<PublicSettingsOptions, PublicSettingsOptions>({
    defaults: { version: '' }
  }, options)

  // TODO: Check if the settings format is corret. If not fix corrupted data
  const settings = new ElectronStore<PublicSettings>(fixedOptions)
  logger.debug(`Load public settings from '${settings.path}'`)

  settings.set('version', locals.packageJson.version)

  return settings
}

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

export type PrivateSettingsStore = ElectronStore<PrivateSettings>
export type PrivateSettingsOptions = ElectronStoreOptions<PrivateSettings>

export const initPrivateSettings = async (options: PrivateSettingsOptions, locals: Locals): Promise<PrivateSettingsStore> => {
  const { sharedMemoryManager, auth } = locals

  const sek = await auth.computeSettingsKey()
  const publicSettingsValues = locals.publicSettings.store
  const fixedOptions = _.merge<PrivateSettingsOptions, PrivateSettingsOptions>({
    defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
    encryptionKey: sek,
    fileExtension: 'enc.json'
  }, options)

  // TODO: Check if the settings format is corret. If not fix corrupted data
  const settings = new ElectronStore<PrivateSettings>(fixedOptions)
  logger.debug(`Load encrypted settings from '${settings.path}'`)

  // Clean public settings
  locals.publicSettings.clear()
  locals.publicSettings.set({
    version: publicSettingsValues.version,
    auth: publicSettingsValues.auth
  })

  const providers = settings.get('providers')

  // Setup default providers
  if (!validProviders(providers)) {
    settings.set('providers', [
      { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' },
      { name: 'Rinkeby', provider: 'did:ethr:rinkeby', network: 'rinkeby', rpcUrl: 'https://rpc.ankr.com/eth_rinkeby' }
    ])
  }

  const wallet = settings.get('wallet')
  wallet.packages = [
    '@i3m/sw-wallet',
    '@i3m/bok-wallet'
  ]
  settings.set('wallet', wallet)

  const secret = settings.get('secret')
  if (secret === undefined) {
    const key = await generateSecret('HS256', { extractable: true })
    const jwk = await exportJWK(key)
    settings.set('secret', jwk)
  }

  // Syncronize shared memory and settings
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: settings.store
  }))
  sharedMemoryManager.on('change', (mem) => {
    settings.set(mem.settings)
  })

  return settings
}
