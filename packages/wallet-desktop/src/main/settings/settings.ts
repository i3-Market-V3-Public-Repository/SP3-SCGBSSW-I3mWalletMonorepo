import { generateSecret, exportJWK } from 'jose'
import _ from 'lodash'
import { digest } from 'object-sha'

import { PrivateSettings, PublicSettings, createDefaultPrivateSettings, Provider } from '@wallet/lib'
import { softwareVersion, Locals, StoreOptions, handleCanBePromise } from '@wallet/main/internal'
import { Store } from '@i3m/base-wallet'

export type PublicSettingsStore = Store<PublicSettings>
export type PublicSettingsOptions = Partial<StoreOptions<PublicSettings>>

// ** PUBLIC SETTINGS **

async function cleanPublicSettings (locals: Locals): Promise<void> {
  const publicSettingsValues = await locals.publicSettings.getStore()

  // Clean public settings
  await locals.publicSettings.clear()
  await locals.publicSettings.set({
    version: publicSettingsValues.version,
    auth: publicSettingsValues.auth,
    enc: publicSettingsValues.enc,
    store: publicSettingsValues.store ?? { type: 'electron-store' }
  })
}

export const initPublicSettings = async (options: PublicSettingsOptions, locals: Locals): Promise<PublicSettingsStore> => {
  const fixedOptions = _.merge<PublicSettingsOptions, PublicSettingsOptions>({
    defaults: { version: softwareVersion(locals) }
  }, options)

  // TODO: Check if the settings format is corret. If not fix corrupted data

  // NOTE: Public settings must always be not encrypted and using the electorn store.
  // This guarantees compatibilities with future versions!
  const { storeManager } = locals
  const settings = await storeManager.buildStore(fixedOptions, 'electron-store')

  const storeInfo = await settings.get('store')
  if (storeInfo?.type === undefined) {
    await settings.set('store', { type: 'electron-store' })
  }

  return settings
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

export type PrivateSettingsStore = Store<PrivateSettings>
export type PrivateSettingsOptions = Partial<StoreOptions<PrivateSettings>>

export const initPrivateSettings = async (options: PrivateSettingsOptions, locals: Locals): Promise<PrivateSettingsStore> => {
  const { sharedMemoryManager, keysManager: auth, storeManager } = locals

  const sek = await auth.computeSettingsKey()
  const publicSettingsValues = await locals.publicSettings.getStore()
  const fixedOptions = _.merge<PrivateSettingsOptions, PrivateSettingsOptions>({
    defaults: Object.assign({}, createDefaultPrivateSettings(), publicSettingsValues),
    encryptionKey: sek,
    fileExtension: 'enc.json'
  }, options)

  // TODO: Check if the settings format is corret. If not fix corrupted data
  const settings = await storeManager.buildStore(fixedOptions)

  await cleanPublicSettings(locals)
  const providers = await settings.get('providers')

  // Setup default providers
  if (!validProviders(providers)) {
    await settings.set('providers', [
      { name: 'i3Market', provider: 'did:ethr:i3m', network: 'i3m', rpcUrl: 'http://95.211.3.250:8545' },
      { name: 'Rinkeby', provider: 'did:ethr:rinkeby', network: 'rinkeby', rpcUrl: 'https://rpc.ankr.com/eth_rinkeby' }
    ])
  }

  const wallet = await settings.get('wallet')
  wallet.packages = [
    '@i3m/sw-wallet',
    '@i3m/bok-wallet'
  ]
  await settings.set('wallet', wallet)

  const secret = await settings.get('secret')
  if (secret === undefined) {
    const key = await generateSecret('HS256', { extractable: true })
    const jwk = await exportJWK(key)
    await settings.set('secret', jwk)
  }

  // Syncronize shared memory and settings
  const store = await settings.getStore()
  sharedMemoryManager.update((mem) => ({
    ...mem,
    settings: store
  }))
  sharedMemoryManager.on('change', (mem, oldMem) => {
    const newSha = digest(mem)
    const oldSha = digest(mem)
    if (oldSha !== newSha) {
      const promise = settings.set(mem.settings)
      handleCanBePromise(locals, promise)
    }
  })

  return settings
}
