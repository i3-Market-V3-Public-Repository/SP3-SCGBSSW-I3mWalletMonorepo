import { v4 as uuid } from 'uuid'
import { WalletMetadata } from '@i3m/base-wallet'
import {
  createWalletAction,
  Provider,
  WalletInfo
} from '@wallet/lib'
import { ActionError, ActionHandlerBuilder } from '@wallet/main/internal'

interface WalletCreationForm {
  name: string
  walletMetadata: [string, WalletMetadata]
  provider: Provider
}

export const createWallet: ActionHandlerBuilder<typeof createWalletAction> = (
  locals
) => {
  return {
    type: createWalletAction.type,
    async handle (action) {
      const { sharedMemoryManager, dialog, walletFactory } = locals
      const mem = sharedMemoryManager.memory
      const walletPackages = mem.walletsMetadata

      const walletCreationForm = await dialog.form<WalletCreationForm>({
        title: 'Wallet creation',
        descriptors: {
          name: { type: 'text', message: 'Introduce a name for the wallet', allowCancel: false },
          walletMetadata: {
            type: 'select',
            message: 'Select a wallet type',
            values: Object.entries<WalletMetadata>(walletPackages),
            getText ([walletPackage, walletMetadata]) {
              return walletMetadata.name
            }
          },
          provider: walletFactory.providerSelect(mem.settings.private.providers)
        },
        order: ['name', 'walletMetadata', 'provider']
      })

      if (walletCreationForm === undefined) {
        throw new ActionError('Cannot create wallet. Dialog cancelled', action)
      }

      // Wallet already exists
      if (walletCreationForm.name in mem.settings.private.wallet.wallets) {
        throw new ActionError(`Wallet ${walletCreationForm.name} already exists`, action)
      }

      const wallet: WalletInfo = {
        name: walletCreationForm.name,
        package: walletCreationForm.walletMetadata[0],
        store: uuid(),
        args: {
          provider: `did:ethr:${walletCreationForm.provider.network}`
        }
      }

      const name = walletCreationForm.name
      sharedMemoryManager.update((mem) => ({
        ...mem,
        settings: {
          ...mem.settings,
          private: {
            ...mem.settings.private,
            wallet: {
              ...mem.settings.private.wallet,
  
              // If there is no wallet selected, select this wallet
              current: mem.settings.private.wallet.current ?? name,
  
              // Add the wallet to the wallet map
              wallets: {
                ...mem.settings.private.wallet.wallets,
                [name]: wallet
              }
            }
          }
          }
      }))

      return { response: wallet, status: 201 }
    }
  }
}