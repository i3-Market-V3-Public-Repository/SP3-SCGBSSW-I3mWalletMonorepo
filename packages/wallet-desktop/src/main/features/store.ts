import path from 'path'
import fs from 'fs'
import _ from 'lodash'
import { app } from 'electron'

import ElectronStore from 'electron-store'

import { logger, Locals } from '@wallet/main/internal'

import { FeatureHandler } from './feature-handler'
import { StartFeatureError } from './feature-error'
import { Store, StoreOptions } from './feature-context'

interface StoreFeatureOptions {
  encryption?: {
    enabled?: boolean
    tries?: number
    passwordRegex?: RegExp
  }
  name?: string
  storePath?: string
}

const initStore = (storeOptions: StoreOptions): Store => {
  const store: Store = new ElectronStore(storeOptions)

  const lastDate = store.get('start')
  if (lastDate !== undefined) {
    logger.info(`Previous start at ${lastDate.toString()}`)
  } else {
    logger.info('This is the first time you start this application!')
  }
  store.set('start', new Date())

  return store
}

const recoverStore = async (storeOptions: StoreOptions, locals: Locals): Promise<Store> => {
  const { settings, dialog } = locals

  const walletSettings = settings.get('wallet')
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

  return initStore(storeOptions)
}

interface FileInfo {
  name: string
  cwd: string
  fileExtension: string
}

const buildStoreOptions = (walletName: string, opts: StoreFeatureOptions, locals: Locals): FileInfo => {
  const { settings } = locals

  const name = _.get(opts, 'name', 'wallet')
  const storePath = _.get(opts, 'storePath', path.resolve(app.getPath('userData')))
  const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)

  const walletSettings = settings.get('wallet')
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
    const { settings, auth } = locals
    let store: Store | undefined

    const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)

    const walletSettings = settings.get('wallet')
    if (walletSettings.current === undefined) {
      throw new Error('Cannot initialize store if current wallet is not selected')
    }
    const walletArgs = walletSettings.wallets[walletSettings.current]
    const storeId = walletArgs.store

    const storeOptions: StoreOptions = buildStoreOptions(walletName, opts, locals)

    if (encryptionEnabled) {
      storeOptions.encryptionKey = await auth.computeWalletKey(storeId)
      try {
        store = initStore(storeOptions)
      } catch (ex) {
        if (ex instanceof SyntaxError) {
          store = await recoverStore(storeOptions, locals)
        }
      }
    } else {
      store = initStore(storeOptions)
    }

    if (store === undefined) {
      throw new StartFeatureError('Cannot start store', true)
    }

    locals.featureContext.store = store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }))
  },

  async delete (walletName, opts, locals) {
    const storeOptions = buildStoreOptions(walletName, opts, locals)
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
