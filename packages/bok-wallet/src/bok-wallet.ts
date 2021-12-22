import { BaseWallet, WalletOptions } from '@i3m/base-wallet'
import { ethers } from 'ethers'
import { BokWalletModel } from './types'
import { BokKeyWallet } from './bok-key-wallet'
import { BokWalletError } from './errors'

interface ImportInfo {
  alias: string
  privateKey: string
}

export class BokWallet extends BaseWallet<WalletOptions<BokWalletModel>> {
  async importDid (): Promise<void> {
    const importInfo = await this.dialog.form<ImportInfo>({
      title: 'Import DID',
      descriptors: {
        alias: { type: 'text', message: 'Set an alias for your DID' },
        privateKey: { type: 'text', message: 'Paste the private key' }
      },
      order: ['alias', 'privateKey']
    })
    if (importInfo === undefined) {
      return
    }

    if (!importInfo.privateKey.startsWith('0x')) {
      throw new BokWalletError('Private key must start with 0x')
    }

    const keyWallet = this.getKeyWallet<BokKeyWallet>()
    const key = await keyWallet.import(importInfo.privateKey.substring(2))
    const compressedPublicKey = ethers.utils.computePublicKey(`0x${key.publicKeyHex}`, true)

    await this.veramo.agent.didManagerImport({
      did: `${this.provider}:${compressedPublicKey}`,
      alias: importInfo.alias,
      controllerKeyId: key.kid,
      keys: [{
        ...key,
        type: 'Secp256k1',
        kms: this.veramo.defaultKms
      }],
      provider: this.provider,
      services: []
    })
  }
}
