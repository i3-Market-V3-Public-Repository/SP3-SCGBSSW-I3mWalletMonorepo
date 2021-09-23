import path from 'path'
import _ from 'lodash'
import { app, dialog as electronDialogs } from 'electron'

import ElectronStore from 'electron-store'

import { logger } from '@wallet/main/internal'

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

export const storeFeature: FeatureHandler<StoreFeatureOptions> = {
  name: 'store',
  async start (opts, locals) {
    const { windowManager, settings, dialog } = locals
    let store: Store | undefined

    const name = _.get(opts, 'name', 'wallet')
    const storePath = _.get(opts, 'storePath', path.resolve(app.getPath('userData')))
    const encryptionEnabled: boolean = _.get(opts, 'encryption.enabled', false)
    const tries: number = _.get(opts, 'encryption.tries', 3)
    const passwordRegex: RegExp = _.get(opts, 'encryption.passwordRegex', /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/)
    const passwordRegexMessage: string = _.get(opts, 'encryption.passwordRegexMessage', 'Password must fulfill: \nMinimum eight characters, at least one uppercase letter, one lowercase letter and one number:')

    const walletSettings = settings.get('wallet')
    if (walletSettings.current === undefined) {
      throw new Error('Cannot initialize store if current wallet is not selected')
    }
    const walletArgs = walletSettings.wallets[walletSettings.current]
    const storeId = walletArgs.store
    let leftTries = tries

    const storeOptions: StoreOptions = {
      name: `${name}.${storeId}`,
      cwd: storePath,
      fileExtension: encryptionEnabled ? 'enc.json' : 'json'
    }

    if (encryptionEnabled) {
      const message = (tries: number): string => `Enter the password for the wallet ${walletSettings.current as string}. You have ${tries} left.`

      while (leftTries > 0) {
        const password = await dialog.text({
          message: message(leftTries--),
          allowCancel: false,
          hiddenText: true
        })

        if (password === undefined) {
          break
        }

        const match = password.match(passwordRegex) !== null
        if (!match) {
          electronDialogs.showMessageBoxSync({
            message: passwordRegexMessage
          })
          continue
        }

        try {
          storeOptions.encryptionKey = password
          store = initStore(storeOptions)
          break
        } catch (err) {
          // TODO: Handle error properly
          if (!(err instanceof Error)) {
            logger.error('Unable to load (decrypt) the app storage with the provided password')
            console.trace(err)
            throw new Error('generic error')
          }

          logger.error(`Cannot initialize store: ${err.message}`)
          console.error(err)

          // Show alert
          electronDialogs.showMessageBoxSync({
            message: 'Incorrect password'
          })
        }
      }
    } else {
      store = initStore(storeOptions)
    }

    if (store === undefined) {
      const mainWindow = windowManager.getWindow('Main')
      if (leftTries !== 0) {
        electronDialogs.showMessageBoxSync({
          message: 'Cancelled'
        })
      } else if (mainWindow !== undefined && !mainWindow.isDestroyed()) {
        electronDialogs.showMessageBoxSync({
          message: `Could not read the protected storage after ${tries} tries`
        })
      }

      throw new StartFeatureError('Cannot start store', true)
    }

    locals.featureContext.store = store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: true }))
  },

  async stop (opts, locals) {
    delete locals.featureContext.store
    locals.sharedMemoryManager.update((mem) => ({ ...mem, hasStore: false }))
  }
}
