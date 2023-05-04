import { v4 as uuid } from 'uuid'

import { DEFAULT_PROVIDERS_DATA, Descriptors, WalletMetadata } from "@i3m/base-wallet"

import { Provider, WalletInfo } from "@wallet/lib"
import { Locals, WalletDesktopError } from '@wallet/main/internal'


interface WalletCreationForm {
  name: string
  walletMetadata: [string, WalletMetadata]
  provider: Provider
}

export class WalletFactoryFlows {
  
  constructor (protected locals: Locals) {}

  get walletNames (): string[] {
    return Object.keys(this.locals.sharedMemoryManager.memory.settings.private.wallet.wallets)
  }

  async selectWallet (walletName?: string): Promise<string> {
    const { sharedMemoryManager: shm, dialog } = this.locals
    if (walletName === undefined) {
      walletName = await dialog.select({
        values: this.walletNames
      })
    }

    if (walletName === undefined) {
      throw new WalletDesktopError('cannot change wallet: user cancelled', {
        message: 'Select wallet',
        severity: 'warning',
        details: 'User cancelled'
      })
    }

    if (walletName === shm.memory.settings.public.currentWallet) {
      return walletName
    }

    shm.update((mem) => ({
      ...mem,
      settings: {
        ...mem.settings,
        private: {
          ...mem.settings.private,
          wallet: {
            ...mem.settings.private.wallet
          }
        },
        public: {
          ...mem.settings.public,
          currentWallet: walletName
        }
      },
      identities: {},
      resources: {}
    }))

    return walletName
  }

  async getNewWalletInfo(): Promise<WalletInfo> {
    const { sharedMemoryManager: shm, dialog } = this.locals
    const walletPackages = shm.memory.walletsMetadata
    const privateSettings = shm.memory.settings.private

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
        provider: this.providerSelect(privateSettings.providers)
      },
      order: ['name', 'walletMetadata', 'provider']
    })

    if (walletCreationForm === undefined) {
      throw new WalletDesktopError('cannot create wallet: dialog cancelled', {
        message: 'Create Wallet',
        severity: 'warning',
        details: 'Dialog cancelled by the user.'
      })
    }

    // Wallet already exists
    if (walletCreationForm.name in privateSettings.wallet.wallets) {
      throw new WalletDesktopError(`cannot create wallet: ${walletCreationForm.name} already exists`, {
        message: 'Create Wallet',
        severity: 'warning',
        details: `Wallet ${walletCreationForm.name} already exists`
      })
    }

    return {
      name: walletCreationForm.name,
      package: walletCreationForm.walletMetadata[0],
      store: uuid(),
      args: {
        provider: `did:ethr:${walletCreationForm.provider.network}`
      }
    }
  }

  providerSelect (providers: Provider[]): Descriptors<Provider> {
    const completeProviderList: Provider[] = [
      ...Object.values(DEFAULT_PROVIDERS_DATA).map((provider) => ({
        ...provider,
        name: provider.network
      })),
      ...providers
    ]
    return {
      type: 'select',
      message: 'Select a network',
      values: completeProviderList,
      getText (provider) {
        return provider.name
      }
    }
  }

}
