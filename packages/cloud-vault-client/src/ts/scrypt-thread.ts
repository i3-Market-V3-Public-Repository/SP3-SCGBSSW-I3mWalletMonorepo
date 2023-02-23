import { isMainThread, parentPort, workerData } from 'worker_threads'
import { KeyObject, scrypt } from 'crypto'
import type { KeyDerivationOptions, ScryptOptions } from './key-manager'

export interface scryptThreadWorkerData {
  _name: 'scrypt-thread'
  passwordOrKey: string | KeyObject
  opts: KeyDerivationOptions
}

if (!isMainThread && typeof workerData === 'object' && workerData._name === 'scrypt-thread') {
  const { passwordOrKey, opts } = workerData as scryptThreadWorkerData

  async function scryptThread (passwordOrKey: string | KeyObject, opts: KeyDerivationOptions): Promise<KeyObject> {
    const scryptOptions: ScryptOptions = {
      ...opts.alg_options,
      maxmem: 256 * opts.alg_options.N * opts.alg_options.r
    }
    const password = (typeof passwordOrKey === 'string') ? passwordOrKey : passwordOrKey.export()
    const keyPromise: Promise<any> = new Promise((resolve, reject) => {
      scrypt(password, opts.salt, opts.derived_key_length, scryptOptions, (err, key) => {
        if (err !== null) reject(err)
        resolve(key)
      })
    })
    return await keyPromise
  }

  scryptThread(passwordOrKey, opts).then((derivedKey) => {
    parentPort?.postMessage(derivedKey)
  }).catch(err => {
    throw (err instanceof Error) ? err : new Error(err)
  })
}
