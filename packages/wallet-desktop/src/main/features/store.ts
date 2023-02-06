import path from 'path'
import fs from 'fs'
import _ from 'lodash'
import { app } from 'electron'

import { logger, Locals, StartFeatureError } from '@wallet/main/internal'

import { FeatureHandler } from './feature-handler'
import { WalletStore, WalletStoreOptions } from './feature-context'

interface StoreFeatureOptions {
  encryption?: {
    enabled?: boolean
    tries?: number
    passwordRegex?: RegExp
  }
  name?: string
  storePath?: string
}

const initStore = async (locals: Locals, storeOptions: WalletStoreOptions): Promise<WalletStore> => {
  const store: WalletStore = await locals.storeManager.buildStore(storeOptions)

  const lastDate = await store.get('start')
  if (lastDate !== undefined) {
    logger.info(`Previous start at ${lastDate.toString()}`)
  } else {
    logger.info('This is the first time you start this application!')
  }
  await store.set('start', new Date())

  return store
}

const recoverStore = async (locals: Locals, storeOptions: WalletStoreOptions): Promise<WalletStore> => {
  const { settings, dialog } = locals

  const walletSettings = await settings.get('wallet')
  if (walletSettings.current === undefined) {
    throw new Error('Cannot initialize store if current wallet is not selected')
  }

  const accept = await dialog.confirmation({
    message: 'Seems that the data is stored using an old version. Remove the old wallet to create a new one for this version?',
    acceptMsg: 'Yes',
    rejectMsg: 'No'
  })
  if (accept === true) {
    const file = path.join(storeOptions.cwd ?? '', `${storeOptions.name ?? ''}.${storeOptions.fileExtension ?? ''}`)
    fs.unlinkSync(file)
  }

  return await initStore(locals, storeOptions)
}

interface FileInfo {
  name: string
  cwd: string
  fileExtension: string
}

const buildStoreOptions = async (walletName: string, opts: StoreFeatureOptions, locals: Locals): Promise<FileInfo> => {
  const { settings } = locals

  const name = _.get(opts, 'name', 'wallet')
  const storePath = _.get(opts, 'storePath', path.resolve(app.getPath('userData')))
  const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)

  const walletSettings = await settings.get('wallet')
  const walletArgs = walletSettings.wallets[walletName]
  const storeId = walletArgs.store

  return {
    name: `${name}.${storeId}`,
    cwd: storePath,
    fileExtension: encryptionEnabled ? 'enc.json' : 'json'
  }
}

export const storeFeature: FeatureHandler<StoreFeatureOptions> = {
  name: 'store',

  async start (walletName, opts, locals) {
    const { settings, keysManager: auth } = locals
    let store: WalletStore | undefined

    const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)

    const walletSettings = await settings.get('wallet')
    if (walletSettings.current === undefined) {
      throw new Error('Cannot initialize store if current wallet is not selected')
    }
    const walletArgs = walletSettings.wallets[walletSettings.current]
    const storeId = walletArgs.store

    const storeOptions: WalletStoreOptions = await buildStoreOptions(walletName, opts, locals)

    if (encryptionEnabled) {
      const wk = await auth.computeWalletKey(storeId)
      storeOptions.encryptionKey = wk
      try {
        store = await initStore(locals, storeOptions)
      } catch (ex) {
        if (ex instanceof SyntaxError) {
          store = await recoverStore(locals, storeOptions)
        }
      }
    } else {
      store = await initStore(locals, storeOptions)
    }

    if (store === undefined) {
      throw new StartFeatureError('Cannot start store', true)
    }

    locals.featureContext.store = store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }))
  },

  async delete (walletName, opts, locals) {
    const storeOptions = await buildStoreOptions(walletName, opts, locals)
    const storeFullPath = `${storeOptions.cwd}/${storeOptions.name}.${storeOptions.fileExtension}`

    if (fs.existsSync(storeFullPath)) {
      fs.rmSync(storeFullPath)
    }
  },

  async stop (walletName, opts, locals) {
    delete locals.featureContext.store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: false }))
  }
}
