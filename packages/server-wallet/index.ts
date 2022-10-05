import { Wallet, NullDialog, FileStore, ConsoleToast } from '@i3m/base-wallet'
import { homedir } from 'os'
import { join } from 'path'

import walletBuilder from '@i3m/bok-wallet'
import { mkdirSync } from 'fs'

export interface ServerWalletOptions {
  filepath?: string
  password?: string
}
export async function serverWallet (options?: ServerWalletOptions): Promise<Wallet> {
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

  const dialog = new NullDialog()
  const store = new FileStore(filepath, options?.password)
  const toast = new ConsoleToast()
  return await walletBuilder({ dialog, store, toast })
}
