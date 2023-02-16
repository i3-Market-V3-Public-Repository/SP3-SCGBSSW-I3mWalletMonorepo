import { ConsoleToast, FileStore, NullDialog } from '@i3m/base-wallet'
import { homedir } from 'os'
import { join } from 'path'

import walletBuilder, { BokWallet } from '@i3m/bok-wallet'
import { BokWalletModel, BokWalletOptions } from '@i3m/bok-wallet/types/types'
import { mkdirSync, rmSync } from 'fs'

export interface ServerWallet extends BokWallet {
  dialog: NullDialog
  store: FileStore<BokWalletModel>
  toast: ConsoleToast
}
export interface ServerWalletOptions {
  filepath?: string
  password?: string
  provider?: BokWalletOptions['provider']
  providerData?: BokWalletOptions['providersData']
  reset?: boolean
}

export async function serverWalletBuilder (options?: ServerWalletOptions): Promise<ServerWallet> {
  let filepath: string
  if (options?.filepath === undefined) {
    const filedir = join(homedir(), '.server-wallet')
    try {
      mkdirSync(filedir)
    } catch (error) { }
    filepath = join(filedir, 'store')
  } else {
    filepath = options.filepath
  }
  if (options?.reset === true) {
    try {
      rmSync(filepath)
    } catch (error) { }
  }
  const dialog = new NullDialog()
  const store = new FileStore<BokWalletModel>(filepath, options?.password)
  const toast = new ConsoleToast()
  return await (walletBuilder({
    dialog,
    store,
    toast,
    provider: options?.provider,
    providersData: options?.providerData
  }) as Promise<ServerWallet>)
}
